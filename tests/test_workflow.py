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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pwnabase import candidates, storage, tools, workflow
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
        self.tool.write_text('#!' + sys.executable + '\n' + '''import hashlib, os, pathlib, sys, time
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
elif '--stdin-timeout-abort=0' in args:
    sys.stdin.buffer.read(1)
    sys.exit(1)
else:
    calls_path = os.environ.get('PWNABASE_TEST_HASHCAT_CALLS')
    if calls_path:
        calls = pathlib.Path(calls_path)
        count = int(calls.read_text()) + 1 if calls.exists() else 1
        calls.write_text(str(count))
        batch_log = os.environ.get('PWNABASE_TEST_BATCH_LOG')
        if batch_log and not any('self-test.txt' in arg for arg in args):
            batch = pathlib.Path(args[args.index('--outfile') + 3]).read_bytes()
            with open(batch_log, 'a') as log:
                log.write(str(len(batch.splitlines())) + ' ' + hashlib.sha256(batch).hexdigest() + '\\n')
        if os.environ.get('PWNABASE_TEST_BLOCK_HASHCAT_CALL') == str(count):
            pathlib.Path(os.environ['PWNABASE_TEST_HASHCAT_MARKER']).write_text(str(count))
            time.sleep(30)
    outfile = pathlib.Path(args[args.index('--outfile') + 1])
    lines = pathlib.Path(args[args.index('--outfile') + 3]).read_bytes().splitlines()
    words = [bytes.fromhex(line.decode()) for line in lines] if '--hex-wordlist' in args else lines
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

    def test_transformed_wordlist_uses_confirmed_batches_and_stops_on_recovery(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 9 + b'testpass123\n')
        original_words = self.words.read_bytes()
        output = self.root / 'out'
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            result = workflow.run(replace(self.config(output), ssid_rules=True))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.counts, {'recovered': 1})
        self.assertIn('Candidate batch 1 complete:', log.getvalue())
        self.assertIn('Recovered in candidate batch 2', log.getvalue())
        self.assertNotIn('testpass123', log.getvalue())
        self.assertEqual(self.words.read_bytes(), original_words)
        self.assertEqual(len(list((output / 'complete').glob('*.json'))), 1)
        self.assertEqual(list((output / '.pwnabase').glob('work-*')), [])

    def test_transformed_wordlist_exhaustion_waits_for_all_confirmed_batches(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 9 + b'testpass123\n')
        script = self.tool.read_text().replace(
            "    outfile = pathlib.Path(args[args.index('--outfile') + 1])",
            "    if not any('self-test.txt' in arg for arg in args):\n        sys.exit(1)\n"
            "    outfile = pathlib.Path(args[args.index('--outfile') + 1])")
        self.tool.write_text(script)
        output = self.root / 'out'
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            result = workflow.run(replace(self.config(output), ssid_rules=True))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.counts, {'wordlist_exhausted': 1})
        exhausted = json.loads(next((output / 'exhausted/words').glob('*.json')).read_text())
        self.assertEqual(exhausted['status'], 'wordlist_exhausted')
        self.assertTrue(exhausted['candidate_generation']['source_complete'])
        self.assertEqual(exhausted['candidate_generation']['eligible'], 76_800)
        self.assertIn('Candidate batch 1 complete: 69,120 candidates', log.getvalue())
        self.assertIn('Candidate batch 2 complete: 7,680 candidates', log.getvalue())
        self.assertEqual(list((output / 'tool-error').glob('*.json')), [])

    def test_interrupted_transformed_wordlist_resumes_after_confirmed_batches(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 9 + b'testpass123\n')
        output = self.root / 'out'
        calls, marker = self.root / 'hashcat-calls', self.root / 'blocked-batch'
        batch_log = self.root / 'batch-log'
        env = os.environ.copy()
        env.update(PWNABASE_TEST_HASHCAT_CALLS=str(calls),
                   PWNABASE_TEST_BLOCK_HASHCAT_CALL='3',
                   PWNABASE_TEST_HASHCAT_MARKER=str(marker),
                   PWNABASE_TEST_BATCH_LOG=str(batch_log))
        command = self.command(output) + ['--ssid-rules']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            if not marker.exists():
                stdout, stderr = process.communicate(timeout=2)
                self.fail('synthetic Hashcat did not reach the interrupted batch; '
                          f'exit={process.returncode}\nstdout={stdout}\nstderr={stderr}')
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assertIn('Interrupted.', stderr)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()

        checkpoints = list((output / '.pwnabase' / 'checkpoints').glob('*.json'))
        self.assertEqual(len(checkpoints), 1)
        checkpoint = json.loads(checkpoints[0].read_text())
        self.assertEqual(checkpoint['cursor']['byte_offset'],
                         len(b'unrelatedfixture\n' * 9))
        self.assertEqual(checkpoint['hashcat_confirmed_candidates'], 69_120)
        self.assertEqual(checkpoint['checkpointed_candidates'], 69_120)
        self.assertFalse(checkpoint['source_complete'])
        self.assertEqual(calls.read_text(), '3')
        self.assertEqual(list((output / '.pwnabase').glob('work-*')), [])
        self.assertEqual(list((output / 'complete').glob('*.json')), [])

        env.pop('PWNABASE_TEST_BLOCK_HASHCAT_CALL')
        resumed = subprocess.run(command, capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn('Resuming transformed wordlist', resumed.stdout)
        self.assertEqual(calls.read_text(), '5')
        batches = batch_log.read_text().splitlines()
        self.assertEqual(batches[0].split()[0], '69120')
        self.assertEqual(batches[1], batches[2])  # Interrupted batch is replayed byte for byte.
        self.assertEqual(batches[2].split()[0], '7680')
        success = json.loads(next((output / 'complete').glob('*.json')).read_text())
        self.assertEqual(success['password'], 'testpass123')
        self.assertEqual(success['candidate_generation']['source_complete'], True)
        self.assertEqual(list((output / 'tool-error').glob('*.json')), [])

    def test_bad_checkpoints_are_preserved_and_other_records_continue(self):
        lines = [tools.synthetic_record(ssid=name) for name in
                 (b'first-network', b'second-network', b'third-network', b'fourth-network')]
        (self.captures / 'capture.pcap').write_text('\n'.join(lines) + '\n')
        output = self.root / 'out'
        info, _ = candidates.load_profile(ROOT / 'rules/ssid.json')
        wordinfo = {'path': str(self.words.resolve()), 'label': 'words',
                    'sha256': storage.fingerprint(self.words)}
        store = storage.ResultStore(output)
        paths = []
        for line in lines[:3]:
            record = tools.parse_record(line)
            _, attempt_key, _ = candidates.attempt_identity(record, wordinfo, info, False, True)
            paths.append(store.checkpoint_path(record['record_id'], attempt_key))
        paths[0].parent.mkdir(parents=True)
        paths[0].write_text('{invalid json')
        paths[1].write_text(json.dumps({'schema_version': 1, 'identity': {'record_id': 'wrong'}}))
        paths[2].write_text('null')
        originals = [path.read_bytes() for path in paths]
        with contextlib.redirect_stdout(io.StringIO()):
            result = workflow.run(replace(self.config(output), ssid_rules=True))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.counts, {'tool_error': 3, 'recovered': 1})
        self.assertEqual([path.read_bytes() for path in paths], originals)
        self.assertEqual(len(list((output / 'tool-error').glob('*.json'))), 3)
        self.assertEqual(len(list((output / 'complete').glob('*.json'))), 1)

    def test_resumed_attempt_exhausts_only_after_replaying_interrupted_batch(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 10)
        output = self.root / 'out'
        calls, marker, batch_log = (self.root / name for name in ('calls', 'marker', 'batches'))
        env = os.environ.copy()
        env.update(PWNABASE_TEST_HASHCAT_CALLS=str(calls),
                   PWNABASE_TEST_BLOCK_HASHCAT_CALL='3',
                   PWNABASE_TEST_HASHCAT_MARKER=str(marker),
                   PWNABASE_TEST_BATCH_LOG=str(batch_log))
        command = self.command(output) + ['--ssid-rules']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists(), 'synthetic Hashcat did not reach the second batch')
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()
        self.assertEqual(list((output / 'exhausted').rglob('*.json')), [])
        env.pop('PWNABASE_TEST_BLOCK_HASHCAT_CALL')
        resumed = subprocess.run(command, capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        exhausted = json.loads(next((output / 'exhausted/words').glob('*.json')).read_text())
        self.assertEqual(exhausted['candidate_generation']['hashcat_confirmed_candidates'], 76800)
        self.assertEqual(exhausted['candidate_generation']['checkpointed_candidates'], 76800)
        batches = batch_log.read_text().splitlines()
        self.assertEqual([row.split()[0] for row in batches], ['69120', '7680', '7680'])
        self.assertEqual(batches[1], batches[2])

    def test_checkpoint_write_failure_reports_confirmed_without_claiming_checkpoint(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n')
        output = self.root / 'out'
        original = storage.atomic_json
        def fail_checkpoint(path, value):
            if path.parent.name == 'checkpoints':
                raise OSError('synthetic checkpoint write failure')
            return original(path, value)
        with patch.object(storage, 'atomic_json', side_effect=fail_checkpoint):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = workflow.run(replace(self.config(output), ssid_rules=True))
        self.assertEqual(result.counts, {'tool_error': 1})
        error = json.loads(next((output / 'tool-error').glob('*.json')).read_text())
        generation = error['candidate_generation']
        self.assertEqual(generation['generated_candidates'], 7680)
        self.assertEqual(generation['hashcat_confirmed_candidates'], 7680)
        self.assertEqual(generation['checkpointed_candidates'], 0)

    def test_explicit_restart_preserves_corrupt_checkpoint_and_recovers(self):
        record = tools.parse_record(tools.synthetic_record())
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        output = self.root / 'out'
        info, _ = candidates.load_profile(ROOT / 'rules/ssid.json')
        wordinfo = {'path': str(self.words.resolve()), 'label': 'words',
                    'sha256': storage.fingerprint(self.words)}
        _, key, _ = candidates.attempt_identity(record, wordinfo, info, False, True)
        checkpoint = storage.ResultStore(output).checkpoint_path(record['record_id'], key)
        checkpoint.parent.mkdir(parents=True)
        checkpoint.write_text('{broken')
        unrelated = checkpoint.parent / 'unrelated.json'
        unrelated.write_text('unrelated')
        result = subprocess.run(self.command(output) + ['--ssid-rules', '--restart-incomplete'],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backups = list((checkpoint.parent / 'backups').glob('*.json'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), '{broken')
        self.assertEqual(unrelated.read_text(), 'unrelated')
        self.assertIn('Restarting incomplete attempt', result.stdout)
        self.assertEqual(len(list((output / 'complete').glob('*.json'))), 1)

    def test_restart_backs_up_matching_identity_and_refuses_mismatch(self):
        checkpoint = self.root / 'checkpoint.json'
        identity = {'record_id': 'synthetic'}
        storage.atomic_json(checkpoint, {'identity': identity, 'progress': 42})
        original = checkpoint.read_bytes()
        backup = storage.backup_checkpoint_for_restart(checkpoint, identity)
        self.assertEqual(backup.read_bytes(), original)
        self.assertFalse(checkpoint.exists())
        storage.atomic_json(checkpoint, {'identity': {'record_id': 'other'}})
        original = checkpoint.read_bytes()
        with self.assertRaises(storage.CheckpointError):
            storage.backup_checkpoint_for_restart(checkpoint, identity)
        self.assertEqual(checkpoint.read_bytes(), original)

    def test_restart_does_not_change_completed_result(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        output = self.root / 'out'
        command = self.command(output) + ['--ssid-rules']
        first = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        completed = next((output / 'complete').glob('*.json'))
        original = completed.read_bytes()
        inode = completed.stat().st_ino
        (self.captures / 'second.pcap').write_text(tools.synthetic_record() + '\n')
        restarted = subprocess.run(command + ['--restart-incomplete'],
                                   capture_output=True, text=True, timeout=20)
        self.assertEqual(restarted.returncode, 0, restarted.stdout + restarted.stderr)
        self.assertEqual(completed.read_bytes(), original)
        self.assertEqual(completed.stat().st_ino, inode)

    def test_explicit_restart_replays_a_previously_confirmed_batch(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 9 + b'testpass123\n')
        output = self.root / 'out'
        calls, marker, log = (self.root / name for name in ('calls', 'marker', 'batches'))
        env = os.environ.copy()
        env.update(PWNABASE_TEST_HASHCAT_CALLS=str(calls), PWNABASE_TEST_BLOCK_HASHCAT_CALL='3',
                   PWNABASE_TEST_HASHCAT_MARKER=str(marker), PWNABASE_TEST_BATCH_LOG=str(log))
        command = self.command(output) + ['--ssid-rules']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()
        checkpoint = next((output / '.pwnabase/checkpoints').glob('*.json'))
        original = checkpoint.read_bytes()
        env.pop('PWNABASE_TEST_BLOCK_HASHCAT_CALL')
        result = subprocess.run(command + ['--restart-incomplete'], capture_output=True,
                                text=True, timeout=20, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backup = next((checkpoint.parent / 'backups').glob('*.json'))
        self.assertEqual(backup.read_bytes(), original)
        batches = log.read_text().splitlines()
        self.assertEqual(batches[0], batches[2])
        self.assertIn('Restarting incomplete attempt', result.stdout)

    def test_light_profile_resumes_after_interrupt(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'unrelatedfixture\n' * 203 + b'testpass123\n')
        output = self.root / 'out'
        calls, marker, log = (self.root / name for name in ('calls', 'marker', 'batches'))
        env = os.environ.copy()
        env.update(PWNABASE_TEST_HASHCAT_CALLS=str(calls), PWNABASE_TEST_BLOCK_HASHCAT_CALL='3',
                   PWNABASE_TEST_HASHCAT_MARKER=str(marker), PWNABASE_TEST_BATCH_LOG=str(log))
        command = self.command(output) + ['--ssid-rules', 'light']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=10)
            self.assertEqual(process.returncode, 130)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
            process.stdout.close()
            process.stderr.close()
        env.pop('PWNABASE_TEST_BLOCK_HASHCAT_CALL')
        resumed = subprocess.run(command, capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
        self.assertIn('Resuming transformed wordlist', resumed.stdout)
        batches = log.read_text().splitlines()
        self.assertEqual(batches[1], batches[2])
        result = json.loads(next((output / 'complete').glob('*.json')).read_text())
        self.assertEqual(result['password'], 'testpass123')

    def test_status_is_read_only_while_batch_lock_is_held(self):
        output = self.root / 'out'
        runtime = output / '.pwnabase'
        checkpoint = runtime / 'checkpoints' / 'synthetic.json'
        identity = {'record_id': 'a' * 64, 'wordlist_sha256': 'b' * 64,
                    'profile_sha256': 'c' * 64, 'generator': candidates.WORDLIST_GENERATOR}
        state = {'schema_version': 1, 'identity': identity, 'cursor': {'byte_offset': 10},
                 'generation': {'seeds': 1, 'generated': 5, 'duplicates': 1,
                                'rejected_length': 1, 'eligible': 3, 'non_utf8_seeds': 0,
                                'generator': candidates.WORDLIST_GENERATOR, 'source_complete': False},
                 'generated_candidates': 3, 'hashcat_confirmed_candidates': 3,
                 'checkpointed_candidates': 3, 'confirmed_batches': 1,
                 'source_complete': False, 'updated_at': '2026-01-01T00:00:00+00:00'}
        storage.atomic_json(checkpoint, state)
        invalid = checkpoint.parent / 'broken.json'
        invalid.write_text('sensitive-fixture-not-json')
        original = {p: p.read_bytes() for p in (checkpoint, invalid)}
        with (runtime / 'batch.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run([sys.executable, str(ROOT / 'recover.py'), '--status',
                                     '--output', str(output), '--hashcat', 'missing-tool',
                                     '--extractor', 'missing-tool'], capture_output=True,
                                    text=True, timeout=10)
        self.assertNotEqual(result.returncode, 2, result.stderr)
        self.assertIn('checkpointed', result.stdout.lower())
        self.assertIn('3', result.stdout)
        self.assertIn('invalid', (result.stdout + result.stderr).lower())
        self.assertNotIn('sensitive-fixture-not-json', result.stdout + result.stderr)
        self.assertEqual({p: p.read_bytes() for p in original}, original)

    def test_generation_progress_is_periodic_and_does_not_reveal_seeds(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'secret-fixture-word\n')
        original_generate = candidates.generate
        def slow_generate(seed, config):
            time.sleep(1.1)
            return original_generate(seed, config)
        for interval in (1, 0):
            log = io.StringIO()
            with self.subTest(interval=interval), patch.object(candidates, 'generate', side_effect=slow_generate):
                with contextlib.redirect_stdout(log):
                    result = workflow.run(replace(self.config(self.root / f'out-{interval}'),
                                                  ssid_rules=True, progress_interval=interval))
                self.assertEqual(result.exit_code, 0)
                self.assertEqual('Generating (completed source words)' in log.getvalue(), bool(interval))
                self.assertNotIn('secret-fixture-word', log.getvalue())
                self.assertNotIn('testpass123', log.getvalue())

    def test_estimate_only_is_read_only_and_reports_separate_categories(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        self.words.write_bytes(b'secret-fixture-word\nsecond-fixture-word\n')
        original = self.words.read_bytes()
        for profile, limit in [('full', '115,201'), ('light', '973')]:
            output = self.root / ('estimate-' + profile)
            saved = output / '.pwnabase' / 'checkpoints' / 'untouched.json'
            saved.parent.mkdir(parents=True)
            saved.write_text('saved-state-fixture')
            command = [sys.executable, str(ROOT / 'recover.py'), '--handshakes', str(self.captures),
                       '--wordlist', str(self.words), '--output', str(output), '--ssid-rules', profile,
                       '--estimate-only', '--hashcat', 'missing-tool', '--extractor', 'missing-tool']
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(limit, result.stdout)
            self.assertIn('words.txt', result.stdout)
            for category in ('Theoretical', 'Sampled', 'Measured throughput', 'unknown'):
                self.assertIn(category, result.stdout)
            self.assertNotIn('secret-fixture-word', result.stdout + result.stderr)
            self.assertEqual(saved.read_text(), 'saved-state-fixture')
            self.assertEqual(list(saved.parent.iterdir()), [saved])
            self.assertEqual(self.words.read_bytes(), original)
        absent = self.root / 'no-output-created'
        command[command.index('--output') + 1] = str(absent)
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(absent.exists())

    def test_normal_transformed_run_reports_workload_before_attempt(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        for profile in ('full', 'light'):
            result = subprocess.run(self.command(self.root / profile) + ['--ssid-rules', profile],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('[Workload estimate]', result.stdout)
            self.assertLess(result.stdout.index('[Workload estimate]'), result.stdout.index('[Recovery]'))
            self.assertIn('runtime and ETA: unknown', result.stdout)
            self.assertNotIn('testpass123', result.stdout + result.stderr)

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
        class IncompleteSource:
            stats = {'source_complete': False}
            def __call__(self, stop):
                yield b'7465737470617373313233\n'

        with self.assertRaisesRegex(tools.ToolError, 'before candidate generation completed'):
            tools.recover(tools.parse_record(tools.synthetic_record()), None,
                          self.config(self.root / 'out'), os.environ.copy(), self.root,
                          use_rules=False, hex_wordlist=True,
                          candidate_stream=IncompleteSource())

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
