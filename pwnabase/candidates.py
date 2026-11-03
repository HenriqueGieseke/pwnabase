"""Candidate sources, profiles, native rules and byte-safe generation."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from . import storage
from .tools import ToolError
import unicodedata

WORDLIST_GENERATOR = 'wordlist-profile-v1'


GENERATOR = 'ssid-v1'
CASES = {'original', 'lower', 'upper', 'title', 'invert_first', 'lower_first_upper_rest'}
OPERATIONS = ['accents', 'case', 'separators', 'substitutions', 'suffixes']
MAX_GENERATED = 1_000_000


def load_profile(path):
    catalog = json.loads(path.read_text(encoding='utf-8'))
    def fail():
        raise ValueError('Invalid SSID profile: expected schema_version 1, type ssid_profile and five supported transformation stages')
    def identifier(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]+', value)
    if (not isinstance(catalog, dict) or type(catalog.get('schema_version')) is not int
            or catalog['schema_version'] != 1 or catalog.get('type') != 'ssid_profile'
            or not identifier(catalog.get('id')) or not isinstance(catalog.get('description'), str)):
        fail()
    rules = catalog.get('rules')
    if not isinstance(rules, list) or len(rules) != len(OPERATIONS):
        fail()
    stages, ids = {}, set()
    for rule in rules:
        if (not isinstance(rule, dict) or not identifier(rule.get('id')) or rule['id'] in ids
                or not isinstance(rule.get('description'), str)
                or rule.get('operation') not in OPERATIONS or rule['operation'] in stages):
            fail()
        ids.add(rule['id'])
        stages[rule['operation']] = rule
    def values(operation, allowed):
        result = stages[operation].get('values')
        if (not isinstance(result, list) or not result
                or any(not isinstance(value, str) or value not in allowed for value in result)
                or len(result) != len(set(result))):
            fail()
        return result
    accents = values('accents', {'preserve', 'strip'})
    cases = values('case', CASES)
    separators = values('separators', {' ', '-', '.', '_', '', 'preserve'})
    profiles = stages['substitutions'].get('profiles')
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 10:
        fail()
    maps, profile_ids = [], set()
    for profile in profiles:
        if (not isinstance(profile, dict) or not identifier(profile.get('id'))
                or profile['id'] in profile_ids or not isinstance(profile.get('description'), str)):
            fail()
        profile_ids.add(profile['id'])
        mapping = profile.get('replacements')
        if not isinstance(mapping, dict) or any(
                not isinstance(k, str) or len(k) != 1 or not ('a' <= k <= 'z')
                or not isinstance(v, str) or len(v) != 1 or not 32 <= ord(v) <= 126
                for k, v in mapping.items()):
            fail()
        maps.append(mapping)
    suffix = stages['suffixes']
    if 'values' in suffix:
        values = suffix['values']
        if (not isinstance(values, list) or not values
                or any(not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,8}', value)
                       for value in values) or len(values) != len(set(values))
                or 'numbers' in suffix or 'years' in suffix):
            fail()
        numbers = ['', *values]
    else:
        for key in ('numbers', 'years'):
            bounds = suffix.get(key)
            if (not isinstance(bounds, dict) or set(bounds) != {'start', 'end'}
                    or any(type(bounds[k]) is not int for k in bounds)
                    or not 0 <= bounds['start'] <= bounds['end'] <= 9999):
                fail()
        numbers = ['', *map(str, range(suffix['numbers']['start'], suffix['numbers']['end'] + 1)),
                   *map(str, range(suffix['years']['start'], suffix['years']['end'] + 1))]
    punctuation = suffix.get('punctuation')
    if (not isinstance(punctuation, list) or not punctuation
            or any(not isinstance(value, str) or value not in {'', '!', '@', '#', '.'} for value in punctuation)
            or len(set(punctuation)) != len(punctuation)):
        fail()
    maximum = 1 + len(accents) * len(cases) * len(separators) * len(maps) * len(numbers) * len(punctuation)
    if maximum > MAX_GENERATED:
        raise ValueError(f'SSID profile exceeds the {MAX_GENERATED:,} candidate-generation limit')
    config = dict(accents=accents, cases=cases, separators=separators, substitutions=maps,
                  numbers=numbers, punctuation=punctuation)
    # Descriptive fields and IDs do not affect behavior or retry identity.
    identity = dict(generator=GENERATOR, unicode_version=unicodedata.unidata_version, config=config)
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(catalog, path=str(path), sha256=digest, generator=GENERATOR,
                unicode_version=unicodedata.unidata_version, maximum_generated=maximum), config


def case_variant(tokens, separator, mode):
    if mode == 'title':
        return separator.join(token[:1].upper() + token[1:].lower() for token in tokens)
    text = separator.join(tokens)
    if mode == 'lower':
        return text.lower()
    if mode == 'upper':
        return text.upper()
    if mode == 'invert_first':
        return text[:1].swapcase() + text[1:]
    if mode == 'lower_first_upper_rest':
        return text[:1].lower() + text[1:].upper()
    return text


def generate(ssid, config):
    """Return eligible byte candidates and counts over all generated combinations."""
    seen, eligible = set(), []
    stats = dict(generated=0, duplicates=0, rejected_length=0, eligible=0,
                 valid_utf8=True, generator=GENERATOR)
    def accept(candidate):
        stats['generated'] += 1
        if candidate in seen:
            stats['duplicates'] += 1
            return
        seen.add(candidate)
        if 8 <= len(candidate) <= 63:
            eligible.append(candidate)
            stats['eligible'] += 1
        else:
            stats['rejected_length'] += 1
    accept(ssid)
    try:
        text = ssid.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        stats['valid_utf8'] = False
        return eligible, stats
    for accent in config['accents']:
        seed = text if accent == 'preserve' else ''.join(
            ch for ch in unicodedata.normalize('NFD', text) if unicodedata.category(ch) != 'Mn')
        tokens = [token for token in re.split(r'[ ._\-]+', seed) if token]
        for mode in config['cases']:
            for separator in config['separators']:
                base = (case_variant([seed], '', mode) if separator == 'preserve'
                        else case_variant(tokens, separator, mode))
                for mapping in config['substitutions']:
                    parts = []
                    for char in base:
                        value = mapping.get(char.lower(), char)
                        if char.isupper() and char.lower() in mapping and value.isalpha():
                            value = value.upper()
                        parts.append(value)
                    mutated = ''.join(parts)
                    for number in config['numbers']:
                        for punctuation in config['punctuation']:
                            accept((mutated + number + punctuation).encode('utf-8'))
    return eligible, stats


def source_info(ssid):
    return dict(type='ssid', label='SSID', ssid_hex=ssid.hex(),
                sha256=hashlib.sha256(ssid).hexdigest(), generator=GENERATOR)


@dataclass(frozen=True)
class CandidateBatch:
    path: Path
    candidate_count: int
    next_offset: int
    source_complete: bool


class WordlistCandidates:
    """Produce bounded hex batches and retain a resumable wordlist cursor.

    Deduplication is per seed; duplicates across different wordlist entries are
    intentionally retained. A batch ends only after a whole source word, so
    its byte offset can resume at a stable wordlist line boundary.
    """
    def __init__(self, path, config, start_offset=0):
        self.path, self.config = path, config
        self.cursor = start_offset
        self._source = None
        self.stats = dict(seeds=0, generated=0, duplicates=0, rejected_length=0,
                          eligible=0, non_utf8_seeds=0, source_complete=False,
                          generator=WORDLIST_GENERATOR)

    def _open_source(self):
        if self._source is not None:
            return
        self._source = self.path.open('rb')
        size = os.fstat(self._source.fileno()).st_size
        if (type(self.cursor) is not int or self.cursor < 0 or self.cursor > size):
            self.close()
            raise ValueError('Checkpoint cursor is outside the current wordlist')
        if self.cursor not in {0, size}:
            self._source.seek(self.cursor - 1)
            if self._source.read(1) != b'\n':
                self.close()
                raise ValueError('Checkpoint cursor is not at a wordlist line boundary')
        self._source.seek(self.cursor)

    def validate_cursor(self, source_complete=False):
        self._open_source()
        size = os.fstat(self._source.fileno()).st_size
        if source_complete and self.cursor != size:
            self.close()
            raise ValueError('Completed checkpoint does not point to the end of the wordlist')

    def next_batch(self, work, candidate_limit):
        if candidate_limit < 1:
            raise ValueError('Candidate batch limit must be positive')
        if self.stats['source_complete']:
            return None
        self._open_source()
        descriptor, filename = tempfile.mkstemp(prefix='candidates-', suffix='.hex', dir=work)
        batch_path = Path(filename)
        count = 0
        keep_file = False
        try:
            with os.fdopen(descriptor, 'wb') as batch_file:
                while count < candidate_limit:
                    line = self._source.readline()
                    if not line:
                        self.stats['source_complete'] = True
                        break
                    next_offset = self._source.tell()
                    seed = line[:-1] if line.endswith(b'\n') else line
                    if seed.endswith(b'\r') and line.endswith(b'\n'):
                        seed = seed[:-1]
                    generated, counts = generate(seed, self.config)
                    self.stats['seeds'] += 1
                    self.stats['non_utf8_seeds'] += not counts['valid_utf8']
                    for key in ('generated', 'duplicates', 'rejected_length', 'eligible'):
                        self.stats[key] += counts[key]
                    for candidate in generated:
                        batch_file.write(candidate.hex().encode('ascii') + b'\n')
                    count += len(generated)
                    self.cursor = next_offset

                if count >= candidate_limit and not self.stats['source_complete']:
                    next_offset = self._source.tell()
                    if not self._source.readline():
                        self.stats['source_complete'] = True
                    self._source.seek(next_offset)

            if not count:
                if not self.stats['source_complete']:
                    raise ValueError('Candidate source ended before generation completed')
                return None
            keep_file = True
            return CandidateBatch(batch_path, count, self.cursor, self.stats['source_complete'])
        finally:
            if not keep_file:
                batch_path.unlink(missing_ok=True)

    def close(self):
        if self._source is not None:
            self._source.close()
            self._source = None

    def __call__(self, stop):
        buffer = bytearray()
        with self.path.open('rb') as stream:
            stream.seek(self.cursor)
            for line in stream:
                if stop.is_set():
                    return
                # Match ordinary LF/CRLF wordlist records, preserving other bytes.
                seed = line[:-1] if line.endswith(b'\n') else line
                if seed.endswith(b'\r') and line.endswith(b'\n'):
                    seed = seed[:-1]
                candidates, counts = generate(seed, self.config)
                self.stats['seeds'] += 1
                self.stats['non_utf8_seeds'] += not counts['valid_utf8']
                for key in ('generated', 'duplicates', 'rejected_length', 'eligible'):
                    self.stats[key] += counts[key]
                for candidate in candidates:
                    if stop.is_set():
                        return
                    buffer.extend(candidate.hex().encode('ascii') + b'\n')
                    if len(buffer) >= 65536:
                        yield bytes(buffer)
                        buffer.clear()
                del candidates
        if buffer and not stop.is_set():
            yield bytes(buffer)
        if not stop.is_set():
            self.stats['source_complete'] = True


def load_rules(path, work):
    catalog = storage.read_json(path)
    if not isinstance(catalog, dict) or type(catalog.get('schema_version')) is not int or catalog['schema_version'] != 1:
        raise ToolError('Rule catalog must have schema_version 1')
    def identifier(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]+', value)
    if not identifier(catalog.get('id')) or not isinstance(catalog.get('description'), str):
        raise ToolError('Rule catalog needs an ID and description')
    rules = catalog.get('rules')
    if not isinstance(rules, list) or not rules:
        raise ToolError('Rule catalog must contain a nonempty rules array')
    seen, expressions = set(), []
    for rule in rules:
        if not isinstance(rule, dict) or not identifier(rule.get('id')) or rule['id'] in seen:
            raise ToolError('Each rule needs a unique ID')
        expression = rule.get('expression')
        if (not isinstance(rule.get('description'), str) or not isinstance(expression, str)
                or not expression or expression.startswith('#')
                or any(ord(char) < 32 or ord(char) > 126 for char in expression)):
            raise ToolError(f'Rule {rule["id"]} needs a description and a single printable ASCII expression')
        seen.add(rule['id'])
        expressions.append(expression)
    digest = hashlib.sha256(json.dumps(expressions, separators=(',', ':')).encode('ascii')).hexdigest()
    native = work / 'selected.rule'
    native.write_text('\n'.join(expressions) + '\n', encoding='ascii')
    return native, dict(catalog, path=str(path), sha256=digest)


def select_profile(ssid, ssid_rules, rules, root):
    selected = storage.read_json(rules.resolve()) if rules and not ssid else None
    wordlist_profile = bool(ssid_rules) or bool(
        isinstance(selected, dict) and selected.get('type') == 'ssid_profile')
    info, config = None, None
    if ssid or wordlist_profile:
        default_profile = 'ssid-light.json' if ssid_rules == 'light' else 'ssid.json'
        info, config = load_profile((rules or root / 'rules' / default_profile).resolve())
    return wordlist_profile, info, config


def snapshot_wordlist(path, work):
    snapshot = work / 'wordlist.txt'
    shutil.copyfile(path, snapshot)
    if not snapshot.stat().st_size:
        raise ToolError('Wordlist is empty')
    label = re.sub(r'[^A-Za-z0-9._-]', '_', path.stem).strip('.') or 'wordlist'
    return snapshot, {'path': str(path), 'label': label, 'sha256': storage.fingerprint(snapshot)}


def estimate_wordlist(path, config, sample_size=3):
    """Count source lines and sample a bounded prefix without saving candidate data."""
    seeds = eligible = sampled = 0
    with path.open('rb') as stream:
        for line in stream:
            seeds += 1
            if sampled < sample_size:
                seed = line[:-1] if line.endswith(b'\n') else line
                if seed.endswith(b'\r') and line.endswith(b'\n'):
                    seed = seed[:-1]
                generated, _ = generate(seed, config)
                eligible += len(generated)
                sampled += 1
    if not seeds:
        raise ToolError('Wordlist is empty')
    return seeds, sampled, eligible


def attempt_identity(record, wordinfo, rules_info, ssid, wordlist_profile):
    source = source_info(bytes.fromhex(record['ssid_hex'])) if ssid else dict(type='wordlist', **wordinfo)
    if wordlist_profile:
        source.update(transformation='ssid_profile', generator=WORDLIST_GENERATOR)
    key = (('ssid-' if ssid else WORDLIST_GENERATOR + '-' if wordlist_profile else '') + source['sha256']
           + ('-' + rules_info['sha256'] if rules_info else ''))
    return source, key, 'ssid' if ssid else wordinfo['label']


def preview(text, config, limit):
    seed = text.encode('utf-8')
    if not 1 <= len(seed) <= 32:
        raise ToolError('Preview SSID must contain 1–32 UTF-8 bytes')
    candidates, stats = generate(seed, config)
    print('SSID preview counts: ' + json.dumps(stats, sort_keys=True))
    limit = min(len(candidates), limit)
    print(f'Sample of {limit} eligible candidates out of {len(candidates)} (no captures read, no recovery):')
    for index in range(limit):
        print(json.dumps(candidates[index * len(candidates) // limit].decode('utf-8'), ensure_ascii=False))


@dataclass(frozen=True)
class PreparedCandidates:
    wordlist_profile: bool = False
    rules_info: dict | None = None
    ssid_config: dict | None = None
    native_rules: Path | None = None
