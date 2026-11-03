"""Configuration shared by CLI callers and local workflow callers."""

from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RunConfig:
    handshakes: Path = ROOT / 'handshakes'
    wordlist: Path | None = None
    output: Path = ROOT
    rules: Path | None = None
    ssid: bool = False
    ssid_rules: bool | str = False
    preview_ssid: str | None = None
    preview_limit: int = 50
    retry_unusable: bool = False
    restart_incomplete: bool = False
    check: bool = False
    status: bool = False
    estimate_only: bool = False
    device_types: str = '2'
    progress_interval: int = 10
    hashcat: str = 'hashcat'
    extractor: str = 'hcxpcapngtool'

    def validate(self):
        ssid = self.ssid or self.preview_ssid is not None
        if self.status and (self.check or self.preview_ssid is not None or self.restart_incomplete):
            raise ValueError('--status cannot be combined with --check, --preview-ssid or --restart-incomplete')
        if self.estimate_only and (self.status or self.check or self.preview_ssid is not None or self.restart_incomplete):
            raise ValueError('--estimate-only cannot be combined with status, check, preview or restart')
        if self.progress_interval < 0:
            raise ValueError('--progress-interval must be nonnegative')
        if self.preview_limit < 1:
            raise ValueError('--preview-limit must be positive')
        if self.preview_ssid is not None and self.check:
            raise ValueError('--preview-ssid and --check cannot be combined')
        if ssid and self.ssid_rules:
            raise ValueError('--ssid-rules is a wordlist option; do not combine it with --ssid or --preview-ssid')
        if self.ssid_rules not in (False, True, 'full', 'light'):
            raise ValueError('Unsupported transformed-wordlist profile')
        if self.ssid_rules == 'light' and self.rules is not None:
            raise ValueError('--ssid-rules light cannot be combined with --rules')
        if ssid and self.wordlist is not None:
            raise ValueError('--wordlist cannot be combined with --ssid or --preview-ssid')
        if self.device_types not in {'1', '2', '1,2'}:
            raise ValueError('Unsupported device types')
    def normalized(self):
        self.validate()
        ssid = self.ssid or self.preview_ssid is not None
        return replace(self, ssid=ssid, output=self.output.resolve(), handshakes=self.handshakes.resolve(),
                       wordlist=None if ssid else (self.wordlist or ROOT / 'SambaTu' / 'SambaTu.txt').resolve())


@dataclass(frozen=True)
class ToolConfig:
    hashcat: str = 'hashcat'
    extractor: str = 'hcxpcapngtool'
    device_types: str = '2'
    native_rules: Path | None = None
