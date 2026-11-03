import argparse
from collections import Counter
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import recover
from pwnabase import tools
import ssid_candidates as ssid
from test_recover import capture_bytes


class SSIDTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = json.loads((recover.ROOT / 'rules/ssid.json').read_text())
        self.profile = self.root / 'profile.json'
        self.save_profile()
        self.info, self.config = ssid.load_profile(self.profile)

    def save_profile(self):
        self.profile.write_text(json.dumps(self.catalog))

    def test_phrase_families_and_counts(self):
        candidates, stats = ssid.generate('num sei só sei que foi assim'.encode(), self.config)
        for expected in ['num-sei-só-sei-que-foi-assim', 'num.sei.só.sei.que.foi.assim',
                         'num_sei_só_sei_que_foi_assim', 'numseisóseiquefoiassim',
                         'Num Sei Só Sei Que Foi Assim', 'NUM SEI SÓ SEI QUE FOI ASSIM',
                         'nUM SEI SÓ SEI QUE FOI ASSIM', 'NumSeiSóSeiQueFoiAssim',
                         'numseisoseiquefoiassim2020!', 'Nvm-$31-$ó-$31-Qv3-F01-@$$1m!']:
            self.assertTrue(expected.encode() in candidates, expected)
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertEqual(stats['generated'], stats['duplicates'] + stats['rejected_length'] + stats['eligible'])
        self.assertTrue(all(8 <= len(candidate) <= 63 for candidate in candidates))

    def test_short_seed_is_extended_before_length_checks(self):
        candidates, stats = ssid.generate(b'abc', self.config)
        self.assertIn(b'abc2000!', candidates)
        self.assertNotIn(b'abc', candidates)
        self.assertGreater(stats['rejected_length'], 0)
        candidates, stats = ssid.generate(b'a', self.config)
        self.assertEqual(candidates, [])
        self.assertEqual(stats['eligible'], 0)

    def test_non_utf8_retains_exact_bytes_and_utf8_uses_byte_lengths(self):
        value = b'\xffab\ncdefg'
        candidates, stats = ssid.generate(value, self.config)
        self.assertEqual(candidates, [value])
        self.assertFalse(stats['valid_utf8'])
        candidates, _ = ssid.generate(('á' * 16).encode(), self.config)
        self.assertTrue(all(len(candidate) <= 63 for candidate in candidates))
        self.assertIn(('á' * 16).encode(), candidates)
        self.assertIn(b'a' * 16, candidates)

    def test_profile_fingerprint_and_validation(self):
        self.catalog['description'] = 'New description'
        self.catalog['id'] = 'renamed'
        self.catalog['rules'][0]['description'] = 'Updated notes'
        self.catalog['rules'][3]['profiles'][0]['id'] = 'new-name'
        self.save_profile()
        self.assertEqual(ssid.load_profile(self.profile)[0]['sha256'], self.info['sha256'])
        self.catalog['rules'][4]['years']['end'] = 2027
        self.save_profile()
        self.assertNotEqual(ssid.load_profile(self.profile)[0]['sha256'], self.info['sha256'])
        self.catalog['rules'][4]['years']['end'] = 9999
        self.save_profile()
        with self.assertRaisesRegex(ValueError, 'limit'):
            ssid.load_profile(self.profile)
        self.catalog['rules'][0]['values'] = ['unsupported']
        self.save_profile()
        with self.assertRaises(ValueError):
            ssid.load_profile(self.profile)

    def test_preview_never_reads_captures_or_runs_tools(self):
        output = io.StringIO()
        with patch.object(tools, 'run_tool') as tool, patch.object(recover, 'process_capture') as process:
            with contextlib.redirect_stdout(output):
                code = recover.main(['--preview-ssid', 'Minha Rede', '--preview-limit', '4',
                                     '--output', str(self.root / 'must-not-exist')])
        self.assertEqual(code, 0)
        self.assertIn('Sample of 4', output.getvalue())
        self.assertFalse((self.root / 'must-not-exist').exists())
        tool.assert_not_called()
        process.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            recover.main(['--ssid', '--wordlist', 'example.txt'])

    def process(self, seed, words=None):
        capture = self.root / 'fixture.pcap'
        capture.write_bytes(b'fixture only')
        args = argparse.Namespace(output=self.root, retry_unusable=False, extractor='extractor',
                                  ssid=True, rules_info=self.info, ssid_config=self.config)
        def extract(command, *unused, **kwargs):
            Path(command[2]).write_text(recover.synthetic_record(ssid=seed) + '\n')
            return 0, ''
        counts = Counter()
        with patch.object(tools, 'run_tool', side_effect=extract), contextlib.redirect_stdout(io.StringIO()):
            recover.process_capture(capture, args, {}, self.root, words, None, counts)
        return counts

    def test_attempt_identity_and_global_success_skip(self):
        # Same wordlist exhaustion cannot suppress an SSID experiment.
        record = recover.parse_record(recover.synthetic_record(ssid=b'Minha Rede'))
        old = self.root / 'exhausted' / 'ssid' / f'{record["record_id"]}-unrelated.json'
        recover.atomic_json(old, {'status': 'wordlist_exhausted'})
        with patch.object(recover, 'recover', return_value=None) as crack:
            self.assertEqual(self.process(b'Minha Rede'), {'candidates_exhausted': 1})
            self.assertEqual(self.process(b'Minha Rede'), {'skipped_candidates_exhausted': 1})
            self.assertEqual(crack.call_count, 1)
            self.catalog['rules'][4]['years']['end'] = 2027
            self.save_profile()
            self.info, self.config = ssid.load_profile(self.profile)
            self.assertEqual(self.process(b'Minha Rede'), {'candidates_exhausted': 1})
            self.assertEqual(crack.call_count, 2)
        with patch.object(recover, 'recover', return_value=b'fixture-password'):
            self.catalog['rules'][4]['years']['end'] = 2028
            self.save_profile()
            self.info, self.config = ssid.load_profile(self.profile)
            self.assertEqual(self.process(b'Minha Rede'), {'recovered': 1})
        result = json.loads(next((self.root / 'complete').glob('*.json')).read_text())
        self.assertEqual(result['candidate_source']['type'], 'ssid')
        self.assertIsNone(result['wordlist'])
        self.assertEqual(result['rules']['id'], self.info['id'])
        self.assertGreater(result['candidate_generation']['eligible'], 0)
        with patch.object(recover, 'recover') as crack:
            self.assertEqual(self.process(b'Minha Rede'), {'skipped_recovered': 1})
            crack.assert_not_called()

    def test_no_eligible_candidates_is_saved_and_skipped_without_hashcat(self):
        with patch.object(recover, 'recover') as crack:
            self.assertEqual(self.process(b'\xff'), {'no_eligible_candidates': 1})
            self.assertEqual(self.process(b'\xff'), {'skipped_no_eligible_candidates': 1})
            crack.assert_not_called()
        self.assertFalse((self.root / 'tool-error').exists())
        result = json.loads(next((self.root / 'exhausted/ssid').glob('*.json')).read_text())
        self.assertEqual(result['candidate_source']['ssid_hex'], 'ff')
        self.assertEqual(result['candidate_generation']['eligible'], 0)


@unittest.skipUnless(os.environ.get('RUN_REAL_TOOLS') == '1', 'set RUN_REAL_TOOLS=1 for real tool tests')
class SSIDRealToolsTests(unittest.TestCase):
    def test_ssid_recovery_pmkid_eapol_and_binary_password(self):
        with tempfile.TemporaryDirectory(prefix='pwnabase-ssid-integration-') as directory:
            root = Path(directory)
            captures = root / 'captures'
            captures.mkdir()
            (captures / 'pmkid.pcap').write_bytes(capture_bytes([('só rede'.encode(), b'SoRede2000!')]))
            (captures / 'eapol.pcap').write_bytes(capture_bytes([(b'minha rede', b'Minha-Rede2000!')], eapol=True))
            profile = json.loads((recover.ROOT / 'rules/ssid.json').read_text())
            profile['rules'][0]['values'] = ['preserve', 'strip']
            profile['rules'][1]['values'] = ['original', 'title']
            profile['rules'][2]['values'] = ['', '-']
            profile['rules'][3]['profiles'] = profile['rules'][3]['profiles'][:1]
            profile['rules'][4].update(numbers={'start': 0, 'end': 1}, years={'start': 2000, 'end': 2000}, punctuation=['', '!'])
            path = root / 'profile.json'
            path.write_text(json.dumps(profile))
            command = [sys.executable, str(recover.ROOT / 'recover.py'), '--ssid', '--rules', str(path),
                       '--handshakes', str(captures), '--output', str(root / 'out'), '--device-types', '1', '--progress-interval', '0']
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            successes = [json.loads(p.read_text()) for p in (root / 'out/complete').glob('*.json')]
            self.assertEqual({item['password'] for item in successes}, {'SoRede2000!', 'Minha-Rede2000!'})
            self.assertTrue(all(item['candidate_source']['type'] == 'ssid' for item in successes))
            self.assertNotIn('SoRede2000!', result.stdout)
            again = subprocess.run(command, capture_output=True, text=True, timeout=300)
            self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
            self.assertIn('"skipped_recovered": 2', again.stdout)
            # Exercise the exact-byte fallback and hex-wordlist transport separately.
            work = root / 'binary'
            work.mkdir()
            password = b'\xffab\ncdefg'
            record = recover.parse_record(recover.synthetic_record(password=password, ssid=password))
            candidates, stats = ssid.generate(password, ssid.load_profile(path)[1])
            self.assertFalse(stats['valid_utf8'])
            words = work / 'binary.hex'
            words.write_text('\n'.join(value.hex() for value in candidates) + '\n')
            args = argparse.Namespace(hashcat='hashcat', device_types='1', native_rules=None)
            env = os.environ.copy()
            runtime = root / 'out/.pwnabase'
            env.update(XDG_DATA_HOME=str(runtime / 'data'), XDG_CACHE_HOME=str(runtime / 'cache'),
                       POCL_CACHE_DIR=str(runtime / 'pocl-cache'), PWNABASE_PROGRESS_INTERVAL='0')
            self.assertEqual(recover.recover(record, words, args, env, work, use_rules=False, hex_wordlist=True), password)
            print('Real tools: accented SSID PMKID/EAPOL recovery, reruns and exact binary candidates passed.')


if __name__ == '__main__':
    unittest.main()
