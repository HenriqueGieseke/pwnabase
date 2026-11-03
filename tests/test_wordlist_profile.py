import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pwnabase import cli
from pwnabase.config import ROOT, RunConfig
from pwnabase.candidates import WordlistCandidates, load_profile
from test_recover import capture_bytes


class WordlistProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.words = self.root / 'words.txt'
        self.info, self.config = load_profile(ROOT / 'rules/ssid.json')

    def test_streaming_is_hex_safe_deduplicates_per_seed_and_accepts_longer_seeds(self):
        # CRLF is a line ending; spaces and other bytes are retained.
        self.words.write_bytes('só casa\r\nsó casa\n'.encode() + b'\xffabcdefg\n' + b'longer-than-thirty-two-characters-wordlist-entry\n')
        stream = WordlistCandidates(self.words, self.config)
        chunks = list(stream(threading.Event()))
        self.assertTrue(all(len(chunk) <= 65664 for chunk in chunks))
        candidates = [bytes.fromhex(line.decode('ascii')) for line in b''.join(chunks).splitlines()]
        self.assertEqual(candidates.count(b'SoCasa2000!'), 2)
        self.assertIn(b'\xffabcdefg', candidates)
        self.assertIn(b'longer-than-thirty-two-characters-wordlist-entry', candidates)
        self.assertEqual(stream.stats['seeds'], 4)
        self.assertEqual(stream.stats['non_utf8_seeds'], 1)
        self.assertTrue(stream.stats['source_complete'])
        self.assertEqual(stream.stats['generated'], stream.stats['eligible'] + stream.stats['duplicates'] + stream.stats['rejected_length'])

    def test_stop_cancels_generation_without_marking_source_complete(self):
        self.words.write_bytes(b'Minha Rede\nOther network\n')
        stop = threading.Event()
        stream = WordlistCandidates(self.words, self.config)
        iterator = stream(stop)
        next(iterator)
        stop.set()
        self.assertEqual(list(iterator), [])
        self.assertEqual(stream.stats['seeds'], 1)
        self.assertFalse(stream.stats['source_complete'])

    def test_default_wordlist_mode_and_conflicting_flags(self):
        config = RunConfig(ssid_rules=True).normalized()
        self.assertEqual(config.wordlist, (ROOT / 'SambaTu/SambaTu.txt').resolve())
        self.assertEqual(load_profile(ROOT / 'rules/ssid.json')[0]['type'], 'ssid_profile')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(['--ssid', '--ssid-rules'])


@unittest.skipUnless(os.environ.get('RUN_REAL_TOOLS') == '1', 'set RUN_REAL_TOOLS=1 for real tool tests')
class WordlistProfileRealToolsTests(unittest.TestCase):
    def test_streamed_unicode_binary_recovery_exhaustion_and_zero_candidates(self):
        with tempfile.TemporaryDirectory(prefix='pwnabase-wordlist-profile-') as directory:
            root = Path(directory)
            captures = root / 'captures'
            captures.mkdir()
            (captures / 'one.pcap').write_bytes(capture_bytes([(b'unrelated-fixture-one', b'SoCasa2000!')]))
            (captures / 'two.pcap').write_bytes(capture_bytes([(b'unrelated-fixture-two', b'\xffabcdefg')]))
            (captures / 'three.pcap').write_bytes(capture_bytes([(b'unrelated-fixture-three', b'not-in-source123!')], eapol=True))
            words = root / 'tiny.txt'
            words.write_bytes('só casa\n'.encode() + b'\xffabcdefg\na\n')
            profile = json.loads((ROOT / 'rules/ssid.json').read_text())
            profile['rules'][1]['values'] = ['original', 'title']
            profile['rules'][2]['values'] = ['']
            profile['rules'][3]['profiles'] = profile['rules'][3]['profiles'][:1]
            profile['rules'][4].update(numbers={'start': 0, 'end': 1}, years={'start': 2000, 'end': 2000}, punctuation=['', '!'])
            config = root / 'profile.json'
            config.write_text(json.dumps(profile))
            command = [sys.executable, str(ROOT / 'recover.py'), '--wordlist', str(words), '--rules', str(config),
                       '--handshakes', str(captures), '--output', str(root / 'out'), '--device-types', '1', '--progress-interval', '0']
            first = subprocess.run(command + ['--ssid-rules'], capture_output=True, text=True, timeout=300)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            output = root / 'out'
            successes = [json.loads(path.read_text()) for path in (output / 'complete').glob('*.json')]
            self.assertEqual({item['password_hex'] for item in successes}, {b'SoCasa2000!'.hex(), b'\xffabcdefg'.hex()})
            self.assertTrue(all(item['candidate_source']['type'] == 'wordlist' for item in successes))
            self.assertTrue(all(item['candidate_source']['transformation'] == 'ssid_profile' for item in successes))
            exhausted = [json.loads(path.read_text()) for path in (output / 'exhausted/tiny').glob('*.json')]
            self.assertEqual(len(exhausted), 1)
            self.assertEqual(exhausted[0]['status'], 'wordlist_exhausted')
            self.assertTrue(exhausted[0]['candidate_generation']['source_complete'])
            self.assertEqual(exhausted[0]['candidate_generation']['seeds'], 3)
            self.assertNotIn('SoCasa2000!', first.stdout)
            # Explicit profile selection without the shortcut is the same experiment.
            again = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
            self.assertIn('"skipped_wordlist_exhausted": 1', again.stdout)
            words.write_bytes(b'a\n')
            empty = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(empty.returncode, 0, empty.stdout + empty.stderr)
            outcomes = [json.loads(path.read_text()) for path in (output / 'exhausted/tiny').glob('*.json')]
            self.assertTrue(any(item['status'] == 'no_eligible_candidates' for item in outcomes))
            print('Real tools: streamed wordlist profiles, binary/Unicode candidates, reruns and zero-candidate outcomes passed.')


if __name__ == '__main__':
    unittest.main()
