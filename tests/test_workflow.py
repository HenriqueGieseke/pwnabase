import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
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
        self.tool.write_text('#!' + sys.executable + '\n' + '''import pathlib, sys
args = sys.argv[1:]
if '--version' in args:
    print('synthetic tool 1')
elif '-I' in args:
    print('Type.....: CPU')
elif '-o' in args:
    source = pathlib.Path(args[2]).read_text()
    if source == 'bad':
        sys.exit(1)
    pathlib.Path(args[1]).write_text(source)
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

    def test_direct_workflow_and_cli_preserve_results_and_reruns(self):
        (self.captures / 'capture.pcap').write_text(tools.synthetic_record() + '\n')
        direct_output, cli_output = self.root / 'direct', self.root / 'cli'
        with contextlib.redirect_stdout(io.StringIO()):
            result = workflow.run(self.config(direct_output))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.counts, {'recovered': 1})
        self.assertEqual(result.records_seen, 1)
        command = [sys.executable, str(ROOT / 'recover.py'), '--handshakes', str(self.captures),
                   '--wordlist', str(self.words), '--output', str(cli_output), '--hashcat', str(self.tool),
                   '--extractor', str(self.tool), '--device-types', '1', '--progress-interval', '0']
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, result.exit_code, completed.stderr)
        first = next((direct_output / 'complete').glob('*.json'))
        second = cli_output / 'complete' / first.name
        a, b = json.loads(first.read_text()), json.loads(second.read_text())
        a.pop('updated_at')
        b.pop('updated_at')
        self.assertEqual(a, b)
        with contextlib.redirect_stdout(io.StringIO()):
            again = workflow.run(self.config(direct_output))
        self.assertEqual(again.counts, {'skipped_recovered': 1})
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)

