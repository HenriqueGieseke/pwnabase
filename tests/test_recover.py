import argparse
from collections import Counter
import contextlib
import hashlib
import hmac
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recover
from pwnabase import tools


def capture_bytes(networks=(), eapol=False):
    """Build wholly synthetic beacon/association/EAPOL traffic; no live radio."""
    frames = []
    rsn = bytes.fromhex('0100000fac040100000fac040100000fac020000')

    def ie(number, data):
        return bytes([number, len(data)]) + data

    def header(fc, dst, src, bssid):
        return struct.pack('<HH', fc, 0) + dst + src + bssid + b'\0\0'

    for index, (ssid, password) in enumerate(networks, 1):
        ap, client = bytes([2, 0, 0, 0, 0, index]), bytes([2, 0, 0, 0, 1, index])
        pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
        pmkid = hmac.new(pmk, b'PMK Name' + ap + client, hashlib.sha1).digest()[:16]
        frames.append(header(0x80, b'\xff' * 6, ap, ap) + struct.pack('<QHH', 0, 100, 0x431)
                      + ie(0, ssid) + ie(1, bytes.fromhex('82848b96')) + ie(3, b'\x01') + ie(48, rsn))
        frames.append(header(0, ap, client, ap) + struct.pack('<HH', 0x431, 10)
                      + ie(0, ssid) + ie(1, bytes.fromhex('82848b96'))
                      + ie(48, rsn if eapol else rsn + struct.pack('<H', 1) + pmkid))
        anonce, snonce = b'\x11' * 32, b'\x22' * 32

        def key_message(info, nonce, data):
            key = (b'\x02' + struct.pack('>HHQ', info, 16, 1) + nonce + b'\0' * 48
                   + struct.pack('>H', len(data)) + data)
            return bytes([2, 3]) + struct.pack('>H', len(key)) + key

        m1 = key_message(0x8a, anonce, b'' if eapol else bytes.fromhex('dd14000fac04') + pmkid)
        llc = bytes.fromhex('aaaa03000000888e')
        frames.append(header(0x208, client, ap, ap) + llc + m1)
        if eapol:
            material = min(ap, client) + max(ap, client) + min(anonce, snonce) + max(anonce, snonce)
            kck = hmac.new(pmk, b'Pairwise key expansion\0' + material + b'\0', hashlib.sha1).digest()[:16]
            m2 = key_message(0x10a, snonce, ie(48, rsn))
            mic = hmac.new(kck, m2, hashlib.sha1).digest()[:16]
            m2 = m2[:81] + mic + m2[97:]
            frames.append(header(0x108, ap, client, ap) + llc + m2)
    result = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
    for index, frame in enumerate(frames):
        result += struct.pack('<IIII', 1700000000, index * 1000, len(frame), len(frame)) + frame
    return result


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.capture = self.root / 'input.pcap'
        self.capture.write_bytes(b'fixture')
        self.words = self.root / 'words.txt'
        self.words.write_bytes(b'testpass123\n')
        self.args = argparse.Namespace(output=self.root, retry_unusable=False, extractor='extractor')
        self.info = {'label': 'words', 'sha256': recover.fingerprint(self.words), 'path': str(self.words)}
        self.good = recover.synthetic_record()
        self.other = recover.synthetic_record(b'different123', b'another-network')

    def extract(self, command, *args, **kwargs):
        Path(command[2]).write_text(self.good + '\n' + self.other + '\n')
        return 0, ''

    def process(self):
        counts = Counter()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            recover.process_capture(self.capture, self.args, {}, self.work, self.words, self.info, counts)
        return counts

    def test_mixed_outcomes_skip_and_changed_wordlist(self):
        before = recover.fingerprint(self.capture)
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(
                recover, 'recover', side_effect=[b'testpass123', None]) as crack:
            self.assertEqual(self.process(), {'recovered': 1, 'wordlist_exhausted': 1})
            self.assertEqual(crack.call_count, 2)
        self.assertEqual(recover.fingerprint(self.capture), before)
        successes = list((self.root / 'complete').glob('*.json'))
        self.assertEqual(len(successes), 1)
        self.assertEqual(recover.read_json(successes[0])['password'], 'testpass123')
        self.assertEqual(successes[0].stat().st_mode & 0o777, 0o600)
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(recover, 'recover') as crack:
            self.assertEqual(self.process(), {'skipped_recovered': 1, 'skipped_wordlist_exhausted': 1})
            crack.assert_not_called()
            self.info['label'] = 'renamed'
            self.assertEqual(self.process()['skipped_wordlist_exhausted'], 1)
            crack.assert_not_called()
        self.words.write_bytes(b'changedpass\n')
        self.info['sha256'] = recover.fingerprint(self.words)
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(
                recover, 'recover', return_value=b'different123') as crack:
            self.assertEqual(self.process(), {'skipped_recovered': 1, 'recovered': 1})
            self.assertEqual(crack.call_count, 1)

    def test_record_error_does_not_stop_next_record_and_is_retried(self):
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(
                recover, 'recover', side_effect=[recover.ToolError('fixture error'), None]):
            self.assertEqual(self.process(), {'tool_error': 1, 'wordlist_exhausted': 1})
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(
                recover, 'recover', return_value=b'testpass123') as crack:
            self.assertEqual(self.process(), {'recovered': 1, 'skipped_wordlist_exhausted': 1})
            self.assertEqual(crack.call_count, 1)
        self.assertEqual(list((self.root / 'tool-error').glob('*.json')), [])

    def test_unusable_skip_retry_and_changed_capture(self):
        with patch.object(tools, 'run_tool', return_value=(0, '')) as extract:
            self.assertEqual(self.process(), {'no_usable_handshake': 1})
            self.assertEqual(self.process(), {'skipped_unusable': 1})
            self.assertEqual(extract.call_count, 1)
            self.args.retry_unusable = True
            self.assertEqual(self.process(), {'no_usable_handshake': 1})
            self.args.retry_unusable = False
            self.capture.write_bytes(b'changed capture')
            self.assertEqual(self.process(), {'no_usable_handshake': 1})
            self.assertEqual(extract.call_count, 3)

    def test_duplicate_capture_retains_both_source_paths(self):
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(
                recover, 'recover', return_value=b'testpass123'):
            self.process()
            duplicate = self.root / 'duplicate.pcap'
            duplicate.write_bytes(self.capture.read_bytes())
            self.capture = duplicate
            self.process()
        for path in (self.root / 'complete').glob('*.json'):
            self.assertEqual(len(recover.read_json(path)['sources']), 2)

    def test_failed_atomic_write_preserves_previous_result(self):
        path = self.root / 'result.json'
        recover.atomic_json(path, {'status': 'old'})
        with patch.object(recover.os, 'replace', side_effect=OSError('fixture disk error')):
            with self.assertRaises(OSError):
                recover.atomic_json(path, {'status': 'new'})
        self.assertEqual(recover.read_json(path), {'status': 'old'})
        self.assertEqual(list(self.root.glob('.pending-*')), [])

    def test_rule_identity_and_exhaustion_are_independent(self):
        catalog = self.root / 'rules.json'
        catalog.write_text((recover.ROOT / 'rules/basic.json').read_text())
        native, info = recover.load_rules(catalog, self.work)
        self.assertEqual(len(native.read_text().splitlines()), 8)
        data = recover.read_json(catalog)
        data['description'] = 'Changed explanation'
        recover.atomic_json(catalog, data)
        self.assertEqual(recover.load_rules(catalog, self.work)[1]['sha256'], info['sha256'])
        with patch.object(tools, 'run_tool', side_effect=self.extract), patch.object(recover, 'recover', return_value=None):
            self.process()
            self.args.rules_info = info
            self.assertEqual(self.process(), {'wordlist_exhausted': 2})
            self.assertEqual(self.process(), {'skipped_wordlist_exhausted': 2})
            data['rules'][0]['expression'] = 'c'
            recover.atomic_json(catalog, data)
            self.args.rules_info = recover.load_rules(catalog, self.work)[1]
            self.assertNotEqual(self.args.rules_info['sha256'], info['sha256'])
            self.assertEqual(self.process(), {'wordlist_exhausted': 2})
        data['rules'][0]['expression'] = 'c\n$!'
        recover.atomic_json(catalog, data)
        with self.assertRaises(recover.ToolError):
            recover.load_rules(catalog, self.work)

    def test_capture_failure_continues_batch(self):
        captures = self.root / 'captures'
        captures.mkdir()
        for name in ('a.pcap', 'b.pcap'):
            (captures / name).write_bytes(b'capture')
        with patch.object(recover, 'preflight'), patch.object(
                recover, 'process_capture', side_effect=[recover.ToolError('bad capture'), None]) as process:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = recover.main(['--handshakes', str(captures), '--wordlist', str(self.words),
                                     '--output', str(self.root / 'out')])
        self.assertEqual(code, 1)
        self.assertEqual(process.call_count, 2)
        self.assertEqual(len(list((self.root / 'out/tool-error').glob('*.json'))), 1)


@unittest.skipUnless(os.environ.get('RUN_REAL_TOOLS') == '1', 'set RUN_REAL_TOOLS=1 for real tool tests')
class RealToolsTests(unittest.TestCase):
    def test_real_extraction_recovery_exhaustion_and_errors(self):
        with tempfile.TemporaryDirectory(prefix='pwnabase-integration-') as directory:
            root = Path(directory)
            captures = root / 'captures'
            captures.mkdir()
            (captures / 'a-corrupt.pcap').write_bytes(b'not a capture')
            (captures / 'b-empty.pcap').write_bytes(capture_bytes())
            (captures / 'c-mixed.pcap').write_bytes(capture_bytes([
                (b'fixture-one', b'correctpass123'), (b'fixture-two', b'Correctpass123!')]))
            (captures / 'd-eapol.pcap').write_bytes(capture_bytes([
                (b'fixture-eapol', b'correctpass123')], eapol=True))
            words = root / 'tiny.txt'
            words.write_bytes(b'wrongpass123\ncorrectpass123\n')
            before = {p.name: recover.fingerprint(p) for p in captures.iterdir()}
            command = [sys.executable, str(recover.ROOT / 'recover.py'), '--handshakes', str(captures),
                       '--wordlist', str(words), '--output', str(root / 'out'), '--device-types', '1']
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            output = root / 'out'
            successes = list((output / 'complete').glob('*.json'))
            self.assertEqual(len(successes), 2, result.stdout + result.stderr)
            self.assertEqual({recover.read_json(p)['record']['kind'] for p in successes}, {'eapol', 'pmkid'})
            self.assertEqual(len(list((output / 'exhausted/tiny').glob('*.json'))), 1)
            self.assertEqual(len(list((output / 'no-usable-handshake').glob('*.json'))), 1)
            self.assertEqual(len(list((output / 'tool-error').glob('*.json'))), 1)
            for path in successes:
                self.assertEqual(recover.read_json(path)['password'], 'correctpass123')
            self.assertEqual(before, {p.name: recover.fingerprint(p) for p in captures.iterdir()})
            self.assertNotIn('correctpass123', result.stdout + result.stderr)
            again = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(again.returncode, 1, again.stdout + again.stderr)
            self.assertIn('"skipped_recovered": 2', again.stdout)
            self.assertIn('"skipped_wordlist_exhausted": 1', again.stdout)
            self.assertIn('"skipped_unusable": 1', again.stdout)
            mutated = subprocess.run(command + ['--rules', str(recover.ROOT / 'rules/basic.json')],
                                     capture_output=True, text=True, timeout=300)
            self.assertEqual(mutated.returncode, 1, mutated.stdout + mutated.stderr)
            successes = list((output / 'complete').glob('*.json'))
            self.assertEqual(len(successes), 3, mutated.stdout + mutated.stderr)
            found = [recover.read_json(p) for p in successes if recover.read_json(p)['password'] == 'Correctpass123!']
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]['rules']['id'], 'basic')
            self.assertEqual(len(list((output / 'exhausted/tiny').glob('*.json'))), 1)
            print('Real tools: plain and mutated recovery, exhaustion identity, errors and reruns passed.')


if __name__ == '__main__':
    unittest.main()
