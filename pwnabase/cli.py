"""Command-line options for local batch recovery."""

import argparse
from pathlib import Path

from . import workflow
from .config import ROOT, RunConfig

DESCRIPTION = 'Local batch recovery of authorized WPA/WPA2 captures. Python 3.10+.'


def main(argv=None):
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--handshakes', type=Path, default=ROOT / 'handshakes')
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument('--wordlist', type=Path)
    source_group.add_argument('--ssid', action='store_true', help='Generate candidates from each record’s own SSID')
    source_group.add_argument('--preview-ssid', metavar='TEXT', help='Preview supplied SSID text only; no captures or recovery')
    parser.add_argument('--preview-limit', type=int, default=50, help='Maximum preview sample size (default 50)')
    parser.add_argument('--output', type=Path, default=ROOT,
                        help='Parent directory for outcome directories and private runtime state')
    parser.add_argument('--rules', type=Path, help='JSON mutation catalog (opt-in)')
    parser.add_argument('--ssid-rules', action='store_true', help='Apply the SSID profile to external wordlist entries (default: SambaTu)')
    parser.add_argument('--retry-unusable', action='store_true')
    parser.add_argument('--check', action='store_true', help='Verify tools and real recovery; process no captures')
    parser.add_argument('--device-types', choices=['1', '2', '1,2'], default='2',
                        help='OpenCL CPU (1), GPU (2, default), or both (1,2)')
    parser.add_argument('--progress-interval', type=int, default=10, help='Seconds between progress updates; 0 disables them')
    parser.add_argument('--hashcat', default='hashcat')
    parser.add_argument('--extractor', default='hcxpcapngtool')
    args = parser.parse_args(argv)
    config = RunConfig(**vars(args))
    try:
        config.validate()
    except ValueError as exc:
        parser.error(str(exc))
    return workflow.run(config).exit_code
