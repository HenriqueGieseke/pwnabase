import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
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

    def test_missing_device_speed_is_reported_as_unknown(self):
        command = [sys.executable, '-c',
                   'import time; print(\'{"progress":[1,10],"devices":[]}\', flush=True); time.sleep(.15)', '-m']
        env = os.environ.copy()
        env['PWNABASE_PROGRESS_INTERVAL'] = '0.03'
        reports = []
        with contextlib.redirect_stdout(io.StringIO()):
            code, _ = tools.run_tool(command, env, self.work, progress_callback=reports.append)
        self.assertEqual(code, 0)
        self.assertEqual(reports, [{'done': 1, 'total': 10}])

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
