"""Sequential local workflow, independent of argument parsing and process exit."""

from collections import Counter
from dataclasses import dataclass, field, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from . import candidates, storage, tools
from .config import ROOT, RunConfig, ToolConfig
from .tools import ToolError

EXTENSIONS = {'.pcap', '.pcapng', '.cap'}


@dataclass
class BatchResult:
    exit_code: int
    counts: dict = field(default_factory=dict)
    records_seen: int = 0
    captures_visited: int = 0


@dataclass
class RunStats:
    records_seen: int = 0
    captures_visited: int = 0


@dataclass
class AttemptResult:
    status: str | None = None
    password: bytes | None = None
    generation: dict | None = None


@dataclass(frozen=True)
class BatchContext:
    config: RunConfig
    candidates: candidates.PreparedCandidates
    tools: ToolConfig
    env: dict
    work: Path
    wordlist: Path | None
    wordinfo: dict | None
    stats: RunStats = field(default_factory=RunStats)


def attempt_record(record, context, outcome):
    work, env, wordlist = context.work, context.env, context.wordlist
    if context.config.ssid:
        generated, outcome.generation = candidates.generate(bytes.fromhex(record['ssid_hex']), context.candidates.ssid_config)
        print('  SSID candidate counts: ' + json.dumps(outcome.generation, sort_keys=True), flush=True)
        if not outcome.generation['valid_utf8']:
            print('  SSID is not valid UTF-8; testing exact bytes only, without text transformations.', flush=True)
        candidate_file = work / 'ssid-candidates.hex'
        with candidate_file.open('w', encoding='ascii') as stream:
            for candidate in generated:
                stream.write(candidate.hex() + '\n')
        outcome.password = tools.recover(record, candidate_file, context.tools, env, work, use_rules=False, hex_wordlist=True) if generated else None
        outcome.status = ('recovered' if outcome.password is not None else
                  'candidates_exhausted' if generated else 'no_eligible_candidates')
    elif context.candidates.wordlist_profile:
        stream = candidates.WordlistCandidates(wordlist, context.candidates.ssid_config)
        try:
            outcome.password = tools.recover(record, None, context.tools, env, work, use_rules=False,
                               hex_wordlist=True, candidate_stream=stream)
        finally:
            outcome.generation = dict(stream.stats)
            print('  Wordlist profile counts: ' + json.dumps(outcome.generation, sort_keys=True), flush=True)
        outcome.status = ('recovered' if outcome.password is not None else
                  'no_eligible_candidates' if not outcome.generation['eligible'] else 'wordlist_exhausted')
    else:
        outcome.password = tools.recover(record, wordlist, context.tools, env, work)
        outcome.status = 'recovered' if outcome.password is not None else 'wordlist_exhausted'


def process_capture(path, context, counts):
    config, prepared = context.config, context.candidates
    env, work = context.env, context.work
    wordlist, wordinfo = context.wordlist, context.wordinfo
    # Work on a byte-for-byte snapshot; never modify or clean original packets.
    snapshot = work / ('capture' + path.suffix.lower())
    shutil.copyfile(path, snapshot)
    capture_id = storage.fingerprint(snapshot)
    source = {'path': str(path), 'sha256': capture_id}
    store = storage.ResultStore(config.output)
    no_usable = store.path('no-usable-handshake', capture_id)
    previous = storage.read_json(no_usable)
    if previous and not config.retry_unusable:
        print('  Skipped: unchanged capture previously yielded no usable handshake.', flush=True)
        storage.add_source(previous, source)
        storage.atomic_json(no_usable, previous)
        counts['skipped_unusable'] += 1
        return 0
    print('  Extracting authentication records...', flush=True)
    records = tools.extract_capture(snapshot, context.tools.extractor, env, work)
    context.stats.records_seen += len(records)
    print(f'  Extracted {len(records)} records: ' + str(dict(Counter(r["kind"] for r in records.values()))), flush=True)
    provenance = store.provenance(capture_id, source, records)
    if not records:
        result = storage.result_base('no_usable_handshake', source, None)
        result['sources'] = provenance['sources']
        storage.atomic_json(no_usable, result)
        print(f'  No usable handshake; saved {no_usable}', flush=True)
        counts['no_usable_handshake'] += 1
        return 0
    store.clear(no_usable)
    for record_id, record in records.items():
        success = store.path('complete', record_id)
        rules_info = prepared.rules_info
        ssid_mode = config.ssid
        wordlist_profile = prepared.wordlist_profile
        candidate_source, attempt_key, label = candidates.attempt_identity(
            record, wordinfo, rules_info, ssid_mode, wordlist_profile)
        exhausted = store.path('exhausted', f'{record_id}-{attempt_key}', label)
        error = store.path('tool-error', f'record-{record_id}')
        outcome = AttemptResult()
        generation = None
        try:
            # Content identity survives renaming a wordlist or its parent folder.
            previous_path, previous = store.previous_attempt(record_id, attempt_key, label)
            if previous:
                print(f'  Skipped {record_id[:12]}: {previous["status"]} (matching saved result).', flush=True)
                for item in provenance['sources']:
                    storage.add_source(previous, item)
                storage.atomic_json(previous_path, previous)
                store.clear(error)
                counts['skipped_' + previous['status']] += 1
                continue
            print(f'  Attempting {record_id[:12]}: SSID={json.dumps(record["ssid"])} BSSID={record["bssid"]}', flush=True)
            attempt_started = time.monotonic()
            attempt_record(record, context, outcome)
            status, password, generation = outcome.status, outcome.password, outcome.generation
            result = storage.result_base(status, source, wordinfo, rules_info)
            result['candidate_source'] = candidate_source
            if generation is not None:
                result['candidate_generation'] = generation
            result['sources'] = provenance['sources']
            result['record'] = record
            if password is not None:
                result['password_hex'] = password.hex()
                try:
                    result['password'] = password.decode('utf-8')
                except UnicodeDecodeError:
                    result['password'] = None
            storage.atomic_json(success if password is not None else exhausted, result)
            store.clear(error)
            print(f'  {status}: {time.monotonic() - attempt_started:.1f}s; saved {success if password is not None else exhausted}', flush=True)
            counts[status] += 1
        except (OSError, ValueError, ToolError) as exc:
            generation = outcome.generation
            result = storage.result_base('tool_error', source, wordinfo, prepared.rules_info)
            result['candidate_source'] = candidate_source
            if generation is not None:
                result['candidate_generation'] = generation
            result.update(record=record, error=str(exc))
            storage.atomic_json(error, result)
            counts['tool_error'] += 1
            print(f'  Record {record_id[:12]}: {exc}; continuing with remaining inputs.', file=sys.stderr, flush=True)

    return len(records)


def run(config):
    batch_started = time.monotonic()
    os.umask(0o077)
    counts = Counter()
    stats = RunStats()
    try:
        config = config.normalized()
        prepared = candidates.PreparedCandidates(*candidates.select_profile(
            config.ssid, config.ssid_rules, config.rules, ROOT))
        if config.preview_ssid is not None:
            candidates.preview(config.preview_ssid, prepared.ssid_config, config.preview_limit)
            return BatchResult(0, dict(counts), stats.records_seen, stats.captures_visited)
        runtime = config.output / '.pwnabase'
        runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (runtime / 'batch.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ToolError('Another batch is already using this output directory') from exc
            with tempfile.TemporaryDirectory(prefix='work-', dir=runtime) as directory:
                work = Path(directory).resolve()
                env = os.environ.copy()
                env.setdefault('RUSTICL_ENABLE', 'radeonsi')
                for variable, folder in [('XDG_DATA_HOME', 'data'), ('XDG_CACHE_HOME', 'cache')]:
                    location = runtime / folder
                    location.mkdir(exist_ok=True, mode=0o700)
                    env[variable] = str(location)
                env['POCL_CACHE_DIR'] = str(runtime / 'pocl-cache')
                env['PWNABASE_PROGRESS_INTERVAL'] = str(config.progress_interval)
                print('PMKID and EAPOL are captured authentication verification records; wordlist exhaustion means no eligible candidate matched.', flush=True)
                print(f'Output: {config.output}; requested OpenCL device types: {config.device_types}', flush=True)
                if config.rules and not config.ssid and not prepared.wordlist_profile:
                    native, info = candidates.load_rules(config.rules.resolve(), work)
                    prepared = replace(prepared, native_rules=native, rules_info=info)
                tool_config = tools.preflight(ToolConfig(config.hashcat, config.extractor,
                                                         config.device_types, prepared.native_rules), env, work)
                if config.ssid or prepared.wordlist_profile:
                    print(f'Generation profile: {prepared.rules_info["id"]}; fingerprint {prepared.rules_info["sha256"][:12]}; candidate generation limit 1,000,000 per seed.', flush=True)
                    if prepared.wordlist_profile:
                        print(f'Applying profile to wordlist entries via streaming stdin: up to {prepared.rules_info["maximum_generated"]:,} combinations per entry before deduplication. Total count and ETA are unavailable; this can substantially increase runtime.', flush=True)
                elif prepared.native_rules:
                    tools.validate_rules(tool_config, prepared.rules_info, env, work)
                else:
                    print('Rules: none; testing original wordlist entries only.', flush=True)
                if config.check:
                    return BatchResult(0, dict(counts), stats.records_seen, stats.captures_visited)
                if not config.handshakes.is_dir():
                    raise ToolError(f'Capture directory does not exist: {config.handshakes}')
                wordlist, wordinfo, label = None, None, 'ssid'
                if not config.ssid:
                    wordlist, wordinfo = candidates.snapshot_wordlist(config.wordlist, work)
                    label = wordinfo['label']
                store = storage.ResultStore(config.output)
                store.prepare(label)
                captures = sorted(p for p in config.handshakes.iterdir()
                                  if p.is_file() and p.suffix.lower() in EXTENSIONS)
                print(f'Found {len(captures)} captures; source: {"each record’s SSID" if config.ssid else config.wordlist.name}.', flush=True)
                context = BatchContext(config, prepared, tool_config, env, work, wordlist, wordinfo, stats)
                for index, path in enumerate(captures, 1):
                    stats.captures_visited += 1
                    print(f'[{index}/{len(captures)}] {path.name}', flush=True)
                    try:
                        process_capture(path, context, counts)
                    except (OSError, ValueError, ToolError) as exc:
                        # Path identity also works for files that cannot be opened/fingerprinted.
                        error_id = hashlib.sha256(str(path).encode()).hexdigest()
                        source = {'path': str(path)}
                        try:
                            source['sha256'] = storage.fingerprint(path)
                        except OSError:
                            pass
                        result = storage.result_base('tool_error', source, wordinfo, prepared.rules_info)
                        result['candidate_source'] = dict(type='ssid', label='SSID') if config.ssid else dict(type='wordlist', **(wordinfo or {}))
                        result['error'] = str(exc)
                        storage.atomic_json(store.path('tool-error', f'path-{error_id}'), result)
                        counts['tool_error'] += 1
                        print(f'  Capture error: {exc}; continuing with remaining inputs.', file=sys.stderr, flush=True)
                    else:
                        error_id = hashlib.sha256(str(path).encode()).hexdigest()
                        store.clear(store.path('tool-error', f'path-{error_id}'))
                print(f'Batch elapsed: {time.monotonic() - batch_started:.1f}s; captures visited: {len(captures)}', flush=True)
                print(f'Authentication records encountered: {stats.records_seen} (including duplicates across captures).', flush=True)
                for label, key in [('Recovered records', 'recovered'), ('Exhausted wordlist records', 'wordlist_exhausted'), ('Exhausted SSID records', 'candidates_exhausted'), ('No eligible candidates', 'no_eligible_candidates'), ('Unusable captures', 'no_usable_handshake'), ('Skipped recovered records', 'skipped_recovered'), ('Skipped exhausted wordlist records', 'skipped_wordlist_exhausted'), ('Skipped exhausted SSID records', 'skipped_candidates_exhausted'), ('Skipped no-eligible-candidate records', 'skipped_no_eligible_candidates'), ('Skipped unusable captures', 'skipped_unusable'), ('Capture or record errors', 'tool_error')]:
                    print(f'  {label}: {counts[key]}', flush=True)
                print('Summary: ' + json.dumps(dict(counts), sort_keys=True), flush=True)
                return BatchResult(1 if counts['tool_error'] else 0, dict(counts), stats.records_seen, stats.captures_visited)
    except KeyboardInterrupt:
        print('\nInterrupted. Completed results are saved; unfinished attempts will restart.', file=sys.stderr)
        return BatchResult(130, dict(counts), stats.records_seen, stats.captures_visited)
    except (OSError, ValueError, ToolError, subprocess.TimeoutExpired) as exc:
        print(f'Cannot run batch: {exc}', file=sys.stderr)
        return BatchResult(2, dict(counts), stats.records_seen, stats.captures_visited)
