"""Private file results, identities, provenance and atomic persistence."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid


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
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def append_event(directory, run_id, event):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / (run_id + '.jsonl')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as stream:
        stream.write(json.dumps(event, ensure_ascii=True, separators=(',', ':')) + '\n')


def append_batch_index(directory, state):
    """Index one configured run using fixed-width, seekable run identifiers."""
    config = state['configuration_id']
    run_id = state['run_id']
    if not re.fullmatch(r'[a-f0-9]{64}', config) or not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise ValueError('Invalid batch index identity')
    metadata = directory / (config + '.json')
    if not metadata.exists():
        atomic_json(metadata, {key: state.get(key) for key in
                                ('configuration_id', 'source_label', 'mode', 'rule_label', 'started_at')})
    fd = os.open(directory / (config + '.idx'), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'ab') as stream:
        size = os.fstat(stream.fileno()).st_size
        if size % 33:
            os.ftruncate(stream.fileno(), size - size % 33)
        stream.write((run_id + '\n').encode('ascii'))
        stream.flush()
        os.fsync(stream.fileno())


def prepare_batch_index(runtime):
    """Create the index once, retaining valid run records from older versions."""
    directory = runtime / 'batch-index'
    if directory.is_symlink():
        raise OSError('Batch index directory cannot be a symlink')
    if directory.is_dir():
        return directory
    runs = []
    run_directory = runtime / 'batch-runs'
    if run_directory.is_symlink():
        raise OSError('Batch run directory cannot be a symlink')
    for path in run_directory.glob('*.json'):
        try:
            if not re.fullmatch(r'[a-f0-9]{32}\.json', path.name) or path.is_symlink():
                continue
            state = read_json(path)
            if (not isinstance(state, dict) or state.get('run_id') != path.stem or
                    not isinstance(state.get('configuration_id'), str) or
                    not re.fullmatch(r'[a-f0-9]{64}', state['configuration_id']) or
                    not isinstance(state.get('started_at'), str)):
                continue
            runs.append(state)
        except (ValueError, UnicodeError):
            continue
    runs.sort(key=lambda item: (item['started_at'], item['run_id']))
    with tempfile.TemporaryDirectory(prefix='.batch-index-', dir=runtime) as temporary:
        target = Path(temporary)
        for state in runs:
            append_batch_index(target, state)
        os.rename(target, directory)
    return directory


def rebuild_batch_index(runtime):
    """Discard a possibly incomplete index; archived run records remain authoritative."""
    directory = runtime / 'batch-index'
    if directory.is_symlink():
        raise OSError('Batch index directory cannot be a symlink')
    if directory.exists():
        shutil.rmtree(directory)
    return prepare_batch_index(runtime)


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


class CheckpointError(ValueError):
    """Saved resume state is unreadable or does not match its attempt."""


def backup_checkpoint_for_restart(path, identity):
    if not path.exists():
        return None
    try:
        saved = read_json(path)
    except (ValueError, UnicodeError, OSError):
        saved = None
    if isinstance(saved, dict) and 'identity' in saved and saved['identity'] != identity:
        raise CheckpointError('Checkpoint identity does not match this attempt; saved state was preserved')
    backup_dir = path.parent / 'backups'
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    name_hash = hashlib.sha256(path.name.encode()).hexdigest()
    backup = backup_dir / f'{name_hash}-{uuid.uuid4().hex}.json'
    os.rename(path, backup)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    directory = os.open(backup_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return backup


def read_checkpoint(path, identity):
    if not path.exists():
        return None
    checkpoint = read_json(path)
    if (not isinstance(checkpoint, dict)
            or type(checkpoint.get('schema_version')) is not int
            or checkpoint['schema_version'] != 1):
        raise CheckpointError('Checkpoint has an unsupported or invalid schema')
    if checkpoint.get('identity') != identity:
        raise CheckpointError('Checkpoint identity does not match this attempt; saved state was preserved')
    cursor = checkpoint.get('cursor')
    if (not isinstance(cursor, dict) or type(cursor.get('byte_offset')) is not int
            or cursor['byte_offset'] < 0):
        raise CheckpointError('Checkpoint cursor is invalid; saved state was preserved')
    generation = checkpoint.get('generation')
    counters = ('seeds', 'generated', 'duplicates', 'rejected_length', 'eligible', 'non_utf8_seeds')
    if (not isinstance(generation, dict)
            or any(type(generation.get(key)) is not int or generation[key] < 0 for key in counters)
            or not isinstance(generation.get('generator'), str)
            or type(generation.get('source_complete')) is not bool):
        raise CheckpointError('Checkpoint generation counts are invalid; saved state was preserved')
    if generation['generator'] != identity.get('generator'):
        raise CheckpointError('Checkpoint generator does not match its identity; saved state was preserved')
    for key in ('hashcat_confirmed_candidates', 'checkpointed_candidates',
                'confirmed_batches', 'generated_candidates'):
        if type(checkpoint.get(key)) is not int or checkpoint[key] < 0:
            raise CheckpointError('Checkpoint progress counts are invalid; saved state was preserved')
    if type(checkpoint.get('source_complete')) is not bool:
        raise CheckpointError('Checkpoint completion state is invalid; saved state was preserved')
    if (checkpoint['generated_candidates'] != generation['eligible']
            or checkpoint['hashcat_confirmed_candidates'] != generation['eligible']
            or checkpoint['checkpointed_candidates'] != generation['eligible']
            or generation['generated'] != (generation['duplicates'] + generation['rejected_length']
                                             + generation['eligible'])
            or checkpoint['source_complete'] != generation['source_complete']
            or checkpoint['confirmed_batches'] < 1):
        raise CheckpointError('Checkpoint progress is inconsistent; saved state was preserved')
    if not isinstance(checkpoint.get('updated_at'), str):
        raise CheckpointError('Checkpoint timestamp is invalid; saved state was preserved')
    return checkpoint


def checkpoint_entries(output, generator):
    """Yield valid saved checkpoints or None for an unreadable entry, without changing state."""
    directory = output / '.pwnabase' / 'checkpoints'
    for path in sorted(directory.glob('*.json')) if directory.is_dir() else []:
        try:
            saved = read_json(path)
            identity = saved.get('identity') if isinstance(saved, dict) else None
            if (not isinstance(identity, dict) or any(
                    not isinstance(identity.get(key), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', identity[key])
                    for key in ('record_id', 'wordlist_sha256', 'profile_sha256'))
                    or identity.get('generator') != generator):
                raise CheckpointError('Invalid checkpoint identity')
            yield read_checkpoint(path, identity)
        except (OSError, ValueError, TypeError, KeyError):
            yield None


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

    def checkpoint_path(self, record_id, attempt_key):
        return self.root / '.pwnabase' / 'checkpoints' / f'{record_id}-{attempt_key}.json'

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
