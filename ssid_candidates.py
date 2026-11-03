"""Deterministic, byte-safe SSID candidate generation; no tool or filesystem writes."""

import hashlib
import json
import re
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
    separators = values('separators', {' ', '-', '.', '_', ''})
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
    for key in ('numbers', 'years'):
        bounds = suffix.get(key)
        if (not isinstance(bounds, dict) or set(bounds) != {'start', 'end'}
                or any(type(bounds[k]) is not int for k in bounds)
                or not 0 <= bounds['start'] <= bounds['end'] <= 9999):
            fail()
    punctuation = suffix.get('punctuation')
    if (not isinstance(punctuation, list) or not punctuation
            or any(not isinstance(value, str) or value not in {'', '!', '@', '#', '.'} for value in punctuation)
            or len(set(punctuation)) != len(punctuation)):
        fail()
    numbers = ['', *map(str, range(suffix['numbers']['start'], suffix['numbers']['end'] + 1)),
               *map(str, range(suffix['years']['start'], suffix['years']['end'] + 1))]
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
                base = case_variant(tokens, separator, mode)
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


class WordlistCandidates:
    """Produce hex-encoded chunks, retaining at most one seed's candidates.

    Deduplication is per seed; duplicates across different wordlist entries are
    intentionally retained so memory does not grow with the whole wordlist.
    """
    def __init__(self, path, config):
        self.path, self.config = path, config
        self.stats = dict(seeds=0, generated=0, duplicates=0, rejected_length=0,
                          eligible=0, non_utf8_seeds=0, source_complete=False,
                          generator=WORDLIST_GENERATOR)

    def __call__(self, stop):
        buffer = bytearray()
        with self.path.open('rb') as stream:
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
