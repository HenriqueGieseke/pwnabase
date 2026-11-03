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
        before = (self.root / '.git/index').read_bytes()
        process = subprocess.Popen([str(self.runner)], cwd=self.root, env=self.env,
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
