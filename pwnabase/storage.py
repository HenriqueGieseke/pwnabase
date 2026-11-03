"""Private file results, identities, provenance and atomic persistence."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


def add_source(result, source):
    sources = result.setdefault('sources', [])
    if source not in sources:
        sources.append(source)


def result_base(status, source, wordlist, rules=None):
    return {'schema_version': 1, 'status': status,
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'sources': [source], 'wordlist': wordlist, 'rules': rules}


class ResultStore:
    """Keep the existing on-disk result contract in one place."""

    def __init__(self, root):
        self.root = Path(root)

    def path(self, kind, identity, label=None):
        if kind == 'capture':
            return self.root / '.pwnabase' / 'captures' / f'{identity}.json'
        if kind == 'exhausted':
            return self.root / 'exhausted' / label / f'{identity}.json'
        return self.root / kind / f'{identity}.json'

    def prepare(self, label):
        for folder in ['complete', f'exhausted/{label}', 'no-usable-handshake', 'tool-error']:
            (self.root / folder).mkdir(parents=True, exist_ok=True, mode=0o700)

    def previous_attempt(self, record_id, attempt_key, label):
        success = self.path('complete', record_id)
        matches = sorted((self.root / 'exhausted').glob(f'*/{record_id}-{attempt_key}.json'))
        path = success if success.exists() else (matches[0] if matches else
                self.path('exhausted', f'{record_id}-{attempt_key}', label))
        return path, read_json(path)

    def provenance(self, capture_id, source, records):
        path = self.path('capture', capture_id)
        result = read_json(path) or {'schema_version': 1, 'sources': []}
        add_source(result, source)
        result['records'] = list(records.values())
        atomic_json(path, result)
        return result

    @staticmethod
    def clear(path):
        path.unlink(missing_ok=True)
