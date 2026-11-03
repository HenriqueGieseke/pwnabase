import contextlib
from dataclasses import replace
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pwnabase import tools, workflow
from pwnabase.config import RunConfig, ROOT


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.captures = self.root / 'captures'
        self.captures.mkdir()
        self.words = self.root / 'words.txt'
        self.words.write_bytes(b'testpass123\n')
        self.tool = self.root / 'fixture-tool'
        self.tool.write_text('#!' + sys.executable + '\n' + '''import os, pathlib, sys, time
args = sys.argv[1:]
if '--version' in args:
    print('synthetic tool 1')
elif '-I' in args:
    print('Type.....: CPU')
elif '-o' in args:
    source = pathlib.Path(args[2]).read_text()
    if source == 'bad':
        sys.exit(1)
    if source == 'wait':
        (pathlib.Path(__file__).parent / 'blocked.pid').write_text(str(os.getpid()))
        time.sleep(30)
    pathlib.Path(args[1]).write_text(source)
elif '--hex-wordlist' in args:
    sys.stdin.buffer.read(1)
    sys.exit(1)
else:
    outfile = pathlib.Path(args[args.index('--outfile') + 1])
    words = pathlib.Path(args[args.index('--outfile') + 3]).read_bytes().splitlines()
    if b'testpass123' not in words:
        sys.exit(1)
    outfile.write_text(b'testpass123'.hex() + '\\n')
''')
        self.tool.chmod(0o700)

    def config(self, output):
        return RunConfig(handshakes=self.captures, wordlist=self.words,
                         output=output, hashcat=str(self.tool), extractor=str(self.tool),
                         device_types='1', progress_interval=0)

    def command(self, output):
        return [sys.executable, str(ROOT / 'recover.py'), '--handshakes', str(self.captures),
                '--wordlist', str(self.words), '--output', str(output), '--hashcat', str(self.tool),
                '--extractor', str(self.tool), '--device-types', '1', '--progress-interval', '0']

    def test_direct_workflow_and_cli_preserve_results_and_reruns(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        direct_output, cli_output = self.root / 'direct', self.root / 'cli'
        with contextlib.redirect_stdout(io.StringIO()):
            result = workflow.run(self.config(direct_output))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.counts, {'recovered': 1})
        self.assertEqual(result.records_seen, 1)
        completed = subprocess.run(self.command(cli_output), capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, result.exit_code, completed.stderr)
        first = next((direct_output / 'complete').glob('*.json'))
        second = cli_output / 'complete' / first.name
        a, b = json.loads(first.read_text()), json.loads(second.read_text())
        # Independently captured from the pre-refactor implementation (4666f55).
        contract = json.loads((Path(__file__).parent / 'fixtures/recovery-contract.json').read_text())
        self.assertEqual(first.name, contract['complete_filename'])
        self.assertEqual(a['record'], contract['record'])
        self.assertEqual(a['wordlist']['sha256'], contract['wordlist_sha256'])
        self.assertEqual(a['password_hex'], contract['password_hex'])
        self.assertEqual(a['password'], contract['password'])
        self.assertEqual(a['schema_version'], 1)
        a.pop('updated_at')
        b.pop('updated_at')
        self.assertEqual(a, b)
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(self.config(direct_output))
        self.assertEqual(again.counts, {'skipped_recovered': 1})
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)

    def test_exhaustion_filename_matches_pre_refactor_contract(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        # Preflight must still recover its fixed known password; target attempts
        # deliberately fail, independent of the candidates supplied.
        source = self.tool.read_text().replace("    outfile = pathlib.Path(args[args.index('--outfile') + 1])",
            "    if not any('self-test.txt' in arg for arg in args):\n        sys.exit(1)\n"
            "    outfile = pathlib.Path(args[args.index('--outfile') + 1])")
        self.tool.write_text(source)
        output = self.root / 'out'
        with contextlib.redirect_stdout(io.StringIO()):
            result = workflow.run(self.config(output))
        self.assertEqual(result.counts, {'wordlist_exhausted': 1})
        contract = json.loads((Path(__file__).parent / 'fixtures/recovery-contract.json').read_text())
        saved = next((output / 'exhausted/words').glob('*.json'))
        self.assertEqual(saved.name, contract['exhausted_filename'])
        data = json.loads(saved.read_text())
        self.assertEqual(data['status'], 'wordlist_exhausted')
        self.assertNotIn('password', data)
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(self.config(output))
        self.assertEqual(again.counts, {'skipped_wordlist_exhausted': 1})

    def test_lock_refusal_and_startup_failure_do_not_process_captures(self):
        output = self.root / 'out'
        runtime = output / '.pwnabase'
        runtime.mkdir(parents=True)
        with (runtime / 'batch.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            completed = subprocess.run(self.command(output), capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 2)
        self.assertIn('Another batch', completed.stderr)
        self.assertNotIn('Checking dependencies', completed.stdout)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            failed = workflow.run(replace(self.config(output), hashcat=str(self.root / 'missing-tool')))
        self.assertEqual(failed.exit_code, 2)
        self.assertEqual(failed.captures_visited, 0)
        self.assertFalse((output / 'complete').exists())
        self.assertEqual(list(runtime.glob('work-*')), [])

    def test_bad_capture_continues_and_retries_on_next_run(self):
        bad = self.captures / 'a-bad.pcap'
        bad.write_text('bad')
        (self.captures / 'b-good.pcap').write_text(tools.synthetic_record() + '\n')
        output = self.root / 'out'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = workflow.run(self.config(output))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.counts, {'tool_error': 1, 'recovered': 1})
        self.assertEqual(result.captures_visited, 2)
        self.assertEqual(len(list((output / 'tool-error').glob('*.json'))), 1)
        bad.write_text('')
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(self.config(output))
        self.assertEqual(again.exit_code, 0)
        self.assertEqual(again.counts, {'no_usable_handshake': 1, 'skipped_recovered': 1})
        self.assertEqual(list((output / 'tool-error').glob('*.json')), [])

    def test_incomplete_stream_is_error_and_never_saved_as_exhausted(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        output = self.root / 'out'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = workflow.run(replace(self.config(output), ssid_rules=True))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.counts, {'tool_error': 1})
        error = json.loads(next((output / 'tool-error').glob('*.json')).read_text())
        self.assertIn('before candidate generation completed', error['error'])
        self.assertFalse(error['candidate_generation']['source_complete'])
        self.assertEqual(list((output / 'exhausted').glob('*/*.json')), [])

    def test_interrupt_preserves_completed_results_and_restart(self):
        (self.captures / 'a-good.pcap').write_text(tools.synthetic_record() + '\n')
        blocked = self.captures / 'b-blocked.pcap'
        blocked.write_text('wait')
        output = self.root / 'out'
        marker = self.root / 'blocked.pid'
        process = subprocess.Popen(self.command(output), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists(), 'synthetic extractor did not start')
            child = int(marker.read_text())
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assertIn('Completed results are saved', stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()
        self.assertEqual(len(list((output / 'complete').glob('*.json'))), 1)
        self.assertEqual(list((output / '.pwnabase').glob('work-*')), [])
        blocked.write_text(tools.synthetic_record(ssid=b'new-fixture') + '\n')
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(self.config(output))
        self.assertEqual(again.counts, {'skipped_recovered': 1, 'recovered': 1})

    def test_legacy_results_keep_global_skip_and_remain_readable_by_viewer(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        output = self.root / 'out'
        with contextlib.redirect_stdout(io.StringIO()):
            workflow.run(self.config(output))
        path = next((output / 'complete').glob('*.json'))
        historical = json.loads(path.read_text())
        for key in ['rules', 'candidate_source', 'candidate_generation']:
            historical.pop(key, None)
        path.write_text(json.dumps(historical))
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(replace(self.config(output), ssid=True, wordlist=None))
        self.assertEqual(again.counts, {'skipped_recovered': 1})
        current = json.loads(path.read_text())
        self.assertEqual(current, historical)
        script = '''import {createStore} from './frontend/server/utils/sheets.mjs';
const sheet = await createStore(process.argv[1]).sheet('complete');
console.log(JSON.stringify(sheet.rows.map(row => ({password: row.password, status: row.status}))));'''
        viewed = subprocess.run(['node', '--input-type=module', '-e', script, str(output)],
                                cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(viewed.returncode, 0, viewed.stderr)
        self.assertEqual(json.loads(viewed.stdout), [{'password': 'testpass123', 'status': 'recovered'}])
