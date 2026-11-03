"""Public check commands exercised against small, wholly synthetic repositories."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CheckRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pwnabase-check-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.env = os.environ.copy()
        # Never let a parent Git hook's repository/index leak into fixture Git.
        for key in subprocess.check_output(['git', 'rev-parse', '--local-env-vars'], text=True).splitlines():
            self.env.pop(key, None)
        self.env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1',
                        RUN_REAL_TOOLS='1', PYTHONDONTWRITEBYTECODE='1')
        self.scratch = Path(self.temp.name) / 'scratch'
        self.scratch.mkdir()
        self.env['TMPDIR'] = str(self.scratch)
        for directory in ['scripts', 'pwnabase', 'tests', 'frontend/tests']:
            (self.root / directory).mkdir(parents=True)
        self.runner = self.root / 'scripts/check'
        shutil.copy2(ROOT / 'scripts/check', self.runner)
        (self.root / 'recover.py').write_text('pass\n')
        (self.root / 'pwnabase/__init__.py').write_text('')
        (self.root / 'frontend/package.json').write_text(json.dumps({'engines': {'node': '>=18.0.0'}}))
        self.test_file = self.root / 'tests/test_fixture.py'
        self.test_file.write_text('''import os, pathlib, subprocess, unittest
class Fixture(unittest.TestCase):
    def test_fixture(self):
        self.assertEqual(os.environ['RUN_REAL_TOOLS'], os.environ.get('EXPECT_REAL', '0'))
        subprocess.run(['node', '--version'], check=True, stdout=subprocess.DEVNULL)
        pathlib.Path(os.environ['PYTHON_MARKER']).write_text('passed')
''')
        (self.root / 'frontend/tests/sheets.test.mjs').write_text('''import {writeFileSync} from 'node:fs';
writeFileSync(process.env.FRONTEND_MARKER, 'passed');
''')
        self.python_marker = Path(self.temp.name) / 'python-passed'
        self.frontend_marker = Path(self.temp.name) / 'frontend-passed'
        self.env.update(PYTHON_MARKER=str(self.python_marker), FRONTEND_MARKER=str(self.frontend_marker))
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic fixture')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], env=self.env, text=True)

    def check(self, *args, env=None):
        return subprocess.run([str(self.runner), *args], cwd=self.root, env=env or self.env,
                              capture_output=True, text=True, timeout=30)

    def test_working_checks_succeed_and_disable_inherited_real_tests(self):
        before = (self.root / '.git/index').read_bytes()
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.python_marker.read_text(), 'passed')
        self.assertEqual(self.frontend_marker.read_text(), 'passed')
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.assertEqual(list(self.root.rglob('__pycache__')), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_compile_and_test_failures_stop_later_checks(self):
        for source, stage in [('invalid syntax !\n', 'Python compilation'),
                              ('import unittest\nclass Bad(unittest.TestCase):\n    def test_bad(self): self.fail("fixture failure")\n', 'Python tests')]:
            with self.subTest(stage=stage):
                self.test_file.write_text(source)
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('FAILED: ' + stage, result.stderr)
                self.assertFalse(self.frontend_marker.exists())
                self.assertEqual(list(self.scratch.iterdir()), [])

    def test_whitespace_failure_stops_before_compilation(self):
        self.test_file.write_text(self.test_file.read_text() + '# trailing space \n')
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAILED: whitespace', result.stderr)
        self.assertNotIn('Checking Python compilation', result.stdout)
        self.assertFalse(self.python_marker.exists())

    def test_staged_snapshot_ignores_opposite_working_changes(self):
        (self.root / 'recover.py').write_text('pass\n# saved fixture change\n')
        self.git('stash', 'push', '-qm', 'fixture stash to preserve')
        original = self.test_file.read_text()
        self.test_file.write_text('import unittest\nclass Bad(unittest.TestCase):\n    def test_bad(self): self.fail("staged failure")\n')
        self.git('add', 'tests/test_fixture.py')
        self.test_file.write_text(original)
        index = (self.root / '.git/index').read_bytes()
        stash = self.git('stash', 'list')
        result = self.check('--staged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('staged failure', result.stderr)
        self.assertEqual((self.root / '.git/index').read_bytes(), index)
        self.assertEqual(self.test_file.read_text(), original)
        self.assertEqual(self.git('stash', 'list'), stash)
        self.assertEqual(list(self.scratch.iterdir()), [])

        self.git('add', 'tests/test_fixture.py')
        self.test_file.write_text('invalid working syntax !\n')
        result = self.check('--staged')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.test_file.read_text(), 'invalid working syntax !\n')
        self.assertEqual(list(self.root.rglob('__pycache__')), [])

    def test_staged_additions_deletions_and_whitespace(self):
        removed = self.root / 'tests/test_removed.py'
        removed.write_text('invalid obsolete syntax !\n')
        self.git('add', str(removed))
        self.git('commit', '-qm', 'obsolete fixture')
        self.git('rm', '--cached', str(removed))
        added = self.root / 'tests/test_added.py'
        added.write_text('import pathlib, unittest\nclass Added(unittest.TestCase):\n'
                         '    def test_added(self): self.assertEqual(pathlib.Path("value.txt").read_text(), "staged")\n')
        value = self.root / 'value.txt'
        value.write_text('staged')
        self.git('add', str(added), str(value))
        value.write_text('unstaged')
        self.test_file.write_text(self.test_file.read_text() + '# unrelated whitespace \n')
        before = (self.root / '.git/index').read_bytes()
        result = self.check('--staged')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(value.read_text(), 'unstaged')
        self.assertEqual(removed.read_text(), 'invalid obsolete syntax !\n')
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.git('add', 'tests/test_fixture.py')
        result = self.check('--staged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAILED: whitespace', result.stderr)

    def test_staged_policy_uses_runtime_outside_snapshot(self):
        local = self.root / 'frontend/.runtime/node_modules/node/bin/node'
        local.parent.mkdir(parents=True)
        local.symlink_to(shutil.which('node'))
        (self.root / 'frontend/package.json').write_text(json.dumps({'engines': {'node': '>=99.0.0'}}))
        result = self.check('--staged')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(local), result.stdout)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_staged_bytes_ignore_unstaged_checkout_attributes(self):
        (self.root / 'value.txt').write_bytes(b'staged\n')
        added = self.root / 'tests/test_bytes.py'
        added.write_text('import pathlib, unittest\nclass Bytes(unittest.TestCase):\n'
                         '    def test_bytes(self): self.assertEqual(pathlib.Path("value.txt").read_bytes(), b"staged\\n")\n')
        self.git('add', 'value.txt', 'tests/test_bytes.py')
        (self.root / '.gitattributes').write_text('value.txt text eol=crlf\n')
        result = self.check('--staged')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_staged_checks_reject_unsupported_index_entries_without_changes(self):
        link = self.root / 'unsafe-link'
        link.symlink_to(self.test_file)
        self.git('add', str(link))
        before = (self.root / '.git/index').read_bytes()
        result = self.check('--staged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('do not support symlinks', result.stderr)
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.git('rm', '--cached', str(link))
        intent = self.root / 'intent.txt'
        intent.write_text('not fully staged')
        self.git('add', '-N', str(intent))
        before = (self.root / '.git/index').read_bytes()
        result = self.check('--staged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('intent-to-add', result.stderr)
        self.assertEqual((self.root / '.git/index').read_bytes(), before)

    def test_staged_checks_reject_unmerged_index(self):
        blob = self.git('rev-parse', 'HEAD:tests/test_fixture.py').strip()
        entries = '0 ' + '0' * 40 + '\ttests/test_fixture.py\n'
        entries += ''.join(f'100644 {blob} {stage}\ttests/test_fixture.py\n' for stage in [1, 2, 3])
        subprocess.run(['git', '-C', str(self.root), 'update-index', '--index-info'],
                       input=entries, env=self.env, text=True, check=True)
        before = (self.root / '.git/index').read_bytes()
        result = self.check('--staged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unmerged index', result.stderr)
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_real_tools_require_explicit_option(self):
        self.env['EXPECT_REAL'] = '1'
        result = self.check('--real-tools')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.python_marker.exists())
        self.assertTrue(self.frontend_marker.exists())

    def test_local_node_is_shared_by_all_checks_and_missing_node_fails(self):
        actual_node = shutil.which('node')
        local = self.root / 'frontend/.runtime/node_modules/node/bin/node'
        local.parent.mkdir(parents=True)
        log = Path(self.temp.name) / 'node-calls'
        local.write_text('#!' + sys.executable + '\nimport os\nfrom pathlib import Path\n'
                         + f'with Path({str(log)!r}).open("a") as stream: stream.write("node\\n")\n'
                         + f'os.execv({actual_node!r}, [{actual_node!r}, *os.sys.argv[1:]])\n')
        local.chmod(0o700)
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(log.read_text().splitlines(), ['node', 'node', 'node'])
        # No local runtime and no Node on PATH: required checks must fail.
        local.unlink()
        minimal = Path(self.temp.name) / 'bin'
        minimal.mkdir()
        (minimal / 'python3').symlink_to(sys.executable)
        (minimal / 'git').symlink_to(shutil.which('git'))
        env = dict(self.env, PATH=str(minimal))
        result = self.check(env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No compatible Node found', result.stderr)

    def test_interrupt_stops_child_and_cleans_temporary_state(self):
        self.interrupt_check(staged=False)

    def test_staged_interrupt_preserves_index_and_cleans_snapshot(self):
        self.interrupt_check(staged=True)

    def interrupt_check(self, staged):
        marker = Path(self.temp.name) / 'running.pid'
        descendant = Path(self.temp.name) / 'descendant.pid'
        stubborn = ('import os, pathlib, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                    + f'pathlib.Path({str(descendant)!r}).write_text(str(os.getpid())); time.sleep(30)')
        self.test_file.write_text('import os, pathlib, subprocess, sys, time, unittest\n'
                                 'class Slow(unittest.TestCase):\n'
                                 '    def test_slow(self):\n'
                                 + f'        subprocess.Popen([sys.executable, "-c", {stubborn!r}])\n'
                                 + f'        while not pathlib.Path({str(descendant)!r}).exists(): time.sleep(.01)\n'
                                 + f'        pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n'
                                 '        time.sleep(30)\n')
        if staged:
            self.git('add', 'tests/test_fixture.py')
        before = (self.root / '.git/index').read_bytes()
        process = subprocess.Popen([str(self.runner), *(['--staged'] if staged else [])], cwd=self.root, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists(), 'fixture check did not start')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            self.assertIn('Interrupted during Python tests', stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)
            status = Path('/proc') / descendant.read_text() / 'stat'
            deadline = time.monotonic() + 2
            while status.exists() and status.read_text().split()[2] != 'Z' and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(not status.exists() or status.read_text().split()[2] == 'Z',
                            'descendant survived check cancellation')
        finally:
            if descendant.exists():
                try:
                    os.kill(int(descendant.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()
        self.assertEqual((self.root / '.git/index').read_bytes(), before)
        self.assertFalse(self.frontend_marker.exists())
        self.assertEqual(list(self.scratch.iterdir()), [])
