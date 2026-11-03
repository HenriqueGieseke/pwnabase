import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pwnabase import tools


class ToolExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root

    def test_timeout_stops_child_and_candidate_source(self):
        marker = self.root / 'timed-out.pid'
        stopped = threading.Event()

        class Source:
            def __call__(self, stop):
                try:
                    yield b'61\n'
                    stop.wait(5)
                finally:
                    stopped.set()

        command = [sys.executable, '-c',
                   'import os,time,pathlib; pathlib.Path(' + repr(str(marker))
                   + ').write_text(str(os.getpid())); time.sleep(30)']
        with self.assertRaises(subprocess.TimeoutExpired):
            tools.run_tool(command, os.environ.copy(), self.work, timeout=1,
                           stdin_source=Source())
        self.assertTrue(stopped.is_set())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)

    def test_diagnostics_return_only_tail_without_printing_tool_output(self):
        command = [sys.executable, '-c',
                   'import sys; sys.stdout.write("SECRET" + "x" * 70000 + "TAIL")']
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code, diagnostic = tools.run_tool(command, os.environ.copy(), self.work)
        self.assertEqual(code, 0)
        self.assertEqual(len(diagnostic), 65536)
        self.assertTrue(diagnostic.endswith('TAIL'))
        self.assertNotIn('SECRET', diagnostic)
        self.assertEqual(output.getvalue(), '')

    def test_interrupt_terminates_child(self):
        marker = self.root / 'child.pid'
        command = [sys.executable, '-c',
                   'import os,time,pathlib; pathlib.Path(' + repr(str(marker))
                   + ').write_text(str(os.getpid())); time.sleep(30)']
        original_wait = subprocess.Popen.wait
        children = []

        def interrupted_wait(process, *args, **kwargs):
            if not children:
                children.append(process)
                raise KeyboardInterrupt()
            return original_wait(process, *args, **kwargs)

        with patch.object(subprocess.Popen, 'wait', interrupted_wait):
            with self.assertRaises(KeyboardInterrupt):
                tools.run_tool(command, os.environ.copy(), self.work)
        self.assertIsNotNone(children[0].poll())

    def test_progress_filters_candidates_and_handles_malformed_lines(self):
        command = [sys.executable, '-c',
                   'import time; print("malformed", flush=True); '
                   'print(\'{"progress":[1,10],"devices":[{"speed":3}],"candidate":"SECRET"}\', flush=True); '
                   'time.sleep(.15)', '-m']
        env = os.environ.copy()
        env['PWNABASE_PROGRESS_INTERVAL'] = '0.03'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code, _ = tools.run_tool(command, env, self.work)
        self.assertEqual(code, 0)
        self.assertIn('Progress 1/10', output.getvalue())
        self.assertNotIn('SECRET', output.getvalue())
        env['PWNABASE_PROGRESS_INTERVAL'] = '0'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            tools.run_tool(command, env, self.work)
        self.assertEqual(output.getvalue(), '')

    def test_broken_pipe_when_consumer_finishes_early_does_not_hang(self):
        class Source:
            stats = {'seeds': 0, 'eligible': 0}
            def __call__(self, stop):
                for _ in range(10000):
                    if stop.is_set():
                        return
                    yield b'61\n' * 22000
        command = [sys.executable, '-c', 'import sys; sys.stdin.buffer.read(1)']
        code, _ = tools.run_tool(command, os.environ.copy(), self.root, timeout=5, stdin_source=Source())
        self.assertEqual(code, 0)

    def test_producer_error_is_reported_and_not_exhaustion(self):
        class Source:
            stats = {'seeds': 0, 'eligible': 0}
            def __call__(self, stop):
                yield b'61\n'
                raise OSError('fixture source error')
        command = [sys.executable, '-c', 'import sys; sys.stdin.buffer.read()']
        with self.assertRaisesRegex(tools.ToolError, 'Candidate generation failed'):
            tools.run_tool(command, os.environ.copy(), self.root, timeout=5, stdin_source=Source())

    def batch_runner(self, exit_code=1, sleeping=False):
        calls = self.root / 'batch-calls'
        script = self.root / 'batch-hashcat'
        script.write_text('#!' + sys.executable + '\n' + '''import os, pathlib, sys, time
args = sys.argv[1:]
outfile = pathlib.Path(args[args.index('--outfile') + 1])
wordlist = pathlib.Path(args[args.index('--outfile') + 3])
with pathlib.Path(os.environ['PWNABASE_BATCH_CALLS']).open('a') as stream:
    stream.write('called\\n')
if os.environ.get('PWNABASE_BATCH_SLEEP'):
    time.sleep(30)
words = [bytes.fromhex(line.decode()) for line in wordlist.read_bytes().splitlines()]
if b'foundpass' in words:
    outfile.write_text(b'foundpass'.hex() + '\\n')
    sys.exit(0)
sys.exit(int(os.environ.get('PWNABASE_BATCH_EXIT', '1')))
''')
        script.chmod(0o700)
        env = os.environ.copy()
        env.update(PWNABASE_BATCH_CALLS=str(calls), PWNABASE_BATCH_EXIT=str(exit_code),
                   PWNABASE_PROGRESS_INTERVAL='0')
        if sleeping:
            env['PWNABASE_BATCH_SLEEP'] = '1'
        return script, calls, env

    def test_recovery_confirms_only_exhausted_batches_and_stops_after_match(self):
        script, calls, env = self.batch_runner()

        class Source:
            def __init__(self):
                self.stats = {'source_complete': False}
            def __call__(self, stop):
                yield b'6161616161616161\n' * 2 + b'666f756e6470617373\n'
                self.stats['source_complete'] = True

        source = Source()
        output = io.StringIO()
        options = SimpleNamespace(hashcat=str(script), device_types='1', native_rules=None)
        with contextlib.redirect_stdout(output):
            password = tools.recover_candidate_batches(
                tools.parse_record(tools.synthetic_record()), source, options, env, self.work,
                initial_batch_size=2, max_batch_size=4, target_seconds=1)
        self.assertEqual(password, b'foundpass')
        self.assertEqual(len(calls.read_text().splitlines()), 2)
        self.assertIn('Candidate batch 1 complete: 2 candidates; Hashcat confirmed exhaustion', output.getvalue())
        self.assertIn('Recovered in candidate batch 2', output.getvalue())
        self.assertFalse(list(self.work.glob('candidates-*.hex')))

    def test_recovery_failure_and_interruption_clean_temporary_batch(self):
        script, calls, env = self.batch_runner(exit_code=2)

        class Source:
            def __init__(self):
                self.stats = {'source_complete': False}
            def __call__(self, stop):
                yield b'6161616161616161\n'
                self.stats['source_complete'] = True

        source = Source()
        options = SimpleNamespace(hashcat=str(script), device_types='1', native_rules=None)
        with self.assertRaisesRegex(tools.ToolError, 'Hashcat recovery failed'):
            tools.recover_candidate_batches(tools.parse_record(tools.synthetic_record()),
                                            source, options, env, self.work)
        self.assertFalse(list(self.work.glob('candidates-*.hex')))

        script, calls, env = self.batch_runner(sleeping=True)
        source = Source()
        original_wait = subprocess.Popen.wait
        children = []
        def interrupted_wait(process, *args, **kwargs):
            if not children:
                children.append(process)
                raise KeyboardInterrupt()
            return original_wait(process, *args, **kwargs)
        with patch.object(subprocess.Popen, 'wait', interrupted_wait):
            with self.assertRaises(KeyboardInterrupt):
                tools.recover_candidate_batches(tools.parse_record(tools.synthetic_record()),
                                                source, options, env, self.work)
        self.assertIsNotNone(children[0].poll())
        self.assertFalse(list(self.work.glob('candidates-*.hex')))

    def test_candidate_generation_failure_does_not_confirm_partial_batch(self):
        script, calls, env = self.batch_runner()

        class FailingSource:
            def __init__(self):
                self.stats = {'source_complete': False}
            def __call__(self, stop):
                yield b'6161616161616161\n'
                raise OSError('synthetic source failure')

        source = FailingSource()
        options = SimpleNamespace(hashcat=str(script), device_types='1', native_rules=None)
        with self.assertRaisesRegex(OSError, 'synthetic source failure'):
            tools.recover_candidate_batches(tools.parse_record(tools.synthetic_record()),
                                            source, options, env, self.work)
        self.assertFalse(calls.exists())
        self.assertFalse(list(self.work.glob('candidates-*.hex')))

    def test_incomplete_final_batch_is_not_sent_to_hashcat(self):
        script, calls, env = self.batch_runner()

        class IncompleteSource:
            stats = {'source_complete': False}
            def __call__(self, stop):
                yield b'6161616161616161\n'

        source = IncompleteSource()
        options = SimpleNamespace(hashcat=str(script), device_types='1', native_rules=None)
        with self.assertRaisesRegex(tools.ToolError, 'before generation completed'):
            tools.recover_candidate_batches(tools.parse_record(tools.synthetic_record()),
                                            source, options, env, self.work,
                                            initial_batch_size=2, max_batch_size=4)
        self.assertFalse(calls.exists())
        self.assertFalse(list(self.work.glob('candidates-*.hex')))
