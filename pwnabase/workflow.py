"""Sequential local workflow, independent of argument parsing and process exit."""

from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from . import candidates, storage, tools
from .monitor import BatchMonitor
from .config import ROOT, RunConfig, ToolConfig
from .tools import ToolError

EXTENSIONS = {'.pcap', '.pcapng', '.cap'}
INITIAL_CANDIDATE_BATCH = 65_536
MAX_CANDIDATE_BATCH = 1_000_000
CANDIDATE_BATCH_TARGET_SECONDS = 60
GENERATION_COUNTERS = ('seeds', 'generated', 'duplicates', 'rejected_length',
                       'eligible', 'non_utf8_seeds')


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


def _checkpoint_age(checkpoint):
    try:
        saved = datetime.fromisoformat(checkpoint['updated_at'])
        age = max(0, int((datetime.now(timezone.utc) - saved).total_seconds()))
        return f'{age:,} seconds ago'
    except (KeyError, TypeError, ValueError, OverflowError):
        return 'age unavailable'


def checkpoint_status(output):
    entries = list(storage.checkpoint_entries(output, candidates.WORDLIST_GENERATOR))
    print('Saved transformed-wordlist checkpoints (in-flight work is not included)\n')
    if not entries:
        print('No saved checkpoints.')
    errors = 0
    for index, saved in enumerate(entries, 1):
        if saved is not None:
            identity = saved['identity']
            print(f'Checkpoint {index}: record {identity["record_id"][:12]}, '
                  f'wordlist {identity["wordlist_sha256"][:12]}, profile {identity["profile_sha256"][:12]}')
            print(f'  Saved {_checkpoint_age(saved)}; source words: {saved["generation"]["seeds"]:,}; '
                  f'byte position: {saved["cursor"]["byte_offset"]:,}')
            print(f'  Generated: {saved["generated_candidates"]:,}; '
                  f'Hashcat-confirmed: {saved["hashcat_confirmed_candidates"]:,}; '
                  f'checkpointed: {saved["checkpointed_candidates"]:,}\n')
        else:
            errors += 1
            print(f'Checkpoint {index}: invalid or unreadable; preserved.\n')
    return BatchResult(1 if errors else 0, {'invalid_checkpoints': errors})


def report_workload(config, prepared, wordlist):
    if not config.handshakes.is_dir():
        raise ToolError(f'Capture directory does not exist: {config.handshakes}')
    captures = sum(1 for path in config.handshakes.iterdir()
                   if path.is_file() and path.suffix.lower() in EXTENSIONS)
    seeds, sampled, eligible = candidates.estimate_wordlist(wordlist, prepared.ssid_config)
    maximum = prepared.rules_info['maximum_generated']
    estimate = (eligible * seeds + sampled // 2) // sampled
    print(f'\n[Workload estimate] {captures:,} capture files; wordlist {config.wordlist.name} '
          f'({seeds:,} entries); '
          f'profile {prepared.rules_info["id"]}.')
    print(f'  Theoretical maximum: {maximum:,} combinations per word; '
          f'{seeds * maximum:,} per authentication record before filtering and deduplication.')
    print(f'  Sampled estimate: about {estimate:,} eligible candidates per record, '
          f'from the first {sampled:,} wordlist entries after filtering and per-word deduplication '
          '(prefix sample may not represent the full wordlist).')
    print('  Capture files may contain multiple records; the total across records is unknown.')
    print('  Measured throughput: unavailable before recovery; runtime and ETA: unknown.\n', flush=True)


def _combined_generation(previous, current):
    result = {
        key: previous.get(key, 0) + current.get(key, 0)
        for key in GENERATION_COUNTERS
    }
    result['generator'] = current.get('generator', previous.get('generator'))
    result['source_complete'] = (current.get('source_complete', False)
                                 or previous.get('source_complete', False))
    return result


def _checkpoint_identity(record, wordinfo, rules_info):
    return {
        'record_id': record['record_id'],
        'wordlist_sha256': wordinfo['sha256'],
        'profile_sha256': rules_info['sha256'],
        'generator': candidates.WORDLIST_GENERATOR,
    }


def _recover_transformed_wordlist(record, context, stream, checkpoint_path,
                                  identity, checkpoint, progress):
    base_generation = dict(checkpoint['generation'])
    base_generated_candidates = checkpoint['generated_candidates']
    base_confirmed_candidates = checkpoint['hashcat_confirmed_candidates']
    base_confirmed_batches = checkpoint['confirmed_batches']
    if checkpoint['source_complete']:
        print('  Saved checkpoint shows the candidate source is complete; finalizing the attempt.',
              flush=True)
        return None
    if checkpoint['checkpointed_candidates']:
        print(f'  Resuming transformed wordlist after {checkpoint["generation"]["seeds"]:,} seeds '
              f'(wordlist byte {checkpoint["cursor"]["byte_offset"]:,}); '
              f'{checkpoint["generated_candidates"]:,} candidates generated, '
              f'{checkpoint["hashcat_confirmed_candidates"]:,} Hashcat-confirmed and '
              f'{checkpoint["checkpointed_candidates"]:,} checkpointed '
              f'({_checkpoint_age(checkpoint)}).', flush=True)

    batch_limit = INITIAL_CANDIDATE_BATCH
    batch_number = base_confirmed_batches
    confirmed_this_run = 0
    while True:
        batch_started = time.monotonic()
        stop_progress = threading.Event()
        def generation_progress():
            while not stop_progress.wait(context.config.progress_interval):
                print(f'  Generating (completed source words): '
                      f'{base_generated_candidates + stream.stats["eligible"]:,} candidates; '
                      f'Hashcat-confirmed: {progress["hashcat_confirmed_candidates"]:,}; '
                      f'checkpointed: {checkpoint["checkpointed_candidates"]:,}.', flush=True)
        reporter = None
        if context.config.progress_interval:
            reporter = threading.Thread(target=generation_progress, daemon=True)
            reporter.start()
        try:
            batch = stream.next_batch(context.work, batch_limit)
        finally:
            stop_progress.set()
            if reporter is not None:
                reporter.join()
        if batch is None:
            if not stream.stats['source_complete']:
                raise ToolError('Candidate source ended before generation completed')
            return None
        try:
            password = tools.recover(record, batch.path, context.tools, context.env,
                                     context.work, use_rules=False, hex_wordlist=True)
            elapsed = max(time.monotonic() - batch_started, 0.001)
            if password is not None:
                print(f'  Recovered in candidate batch {batch_number + 1} after '
                      f'{elapsed:.1f}s total batch time; Hashcat may have stopped before '
                      'testing the full batch.', flush=True)
                return password

            generation = _combined_generation(base_generation, stream.stats)
            generated_candidates = base_generated_candidates + stream.stats['eligible']
            hashcat_confirmed = (base_confirmed_candidates + confirmed_this_run
                                 + batch.candidate_count)
            progress['hashcat_confirmed_candidates'] = hashcat_confirmed
            batch_number += 1
            updated = {
                'schema_version': 1,
                'identity': identity,
                'cursor': {'byte_offset': batch.next_offset},
                'generation': generation,
                'generated_candidates': generated_candidates,
                'hashcat_confirmed_candidates': hashcat_confirmed,
                'checkpointed_candidates': hashcat_confirmed,
                'confirmed_batches': batch_number,
                'source_complete': batch.source_complete,
                'updated_at': datetime.now(timezone.utc).isoformat(),
            }
            storage.atomic_json(checkpoint_path, updated)
            checkpoint.clear()
            checkpoint.update(updated)
            confirmed_this_run += batch.candidate_count
            print(f'  Candidate batch {batch_number} complete: {batch.candidate_count:,} candidates; '
                  f'Hashcat confirmed exhaustion and checkpointed progress in {elapsed:.1f}s total.',
                  flush=True)
            print(f'    Generated: {generated_candidates:,}; Hashcat-confirmed: {hashcat_confirmed:,}; '
                  f'checkpointed: {hashcat_confirmed:,}.\n', flush=True)
            measured_rate = batch.candidate_count / elapsed
            batch_limit = max(1, min(MAX_CANDIDATE_BATCH,
                                     int(measured_rate * CANDIDATE_BATCH_TARGET_SECONDS)))
        finally:
            batch.path.unlink(missing_ok=True)


def attempt_record(record, context, outcome, checkpoint_path=None,
                   checkpoint_identity=None, checkpoint=None):
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
        checkpoint = checkpoint or {
            'cursor': {'byte_offset': 0},
            'generation': {
                'seeds': 0, 'generated': 0, 'duplicates': 0, 'rejected_length': 0,
                'eligible': 0, 'non_utf8_seeds': 0, 'generator': candidates.WORDLIST_GENERATOR,
                'source_complete': False,
            },
            'generated_candidates': 0,
            'hashcat_confirmed_candidates': 0,
            'checkpointed_candidates': 0,
            'confirmed_batches': 0,
            'source_complete': False,
        }
        base_generation = dict(checkpoint['generation'])
        base_generated_candidates = checkpoint['generated_candidates']
        progress = {'hashcat_confirmed_candidates': checkpoint['hashcat_confirmed_candidates']}
        stream = candidates.WordlistCandidates(
            wordlist, context.candidates.ssid_config,
            start_offset=checkpoint['cursor']['byte_offset'])
        try:
            stream.validate_cursor(source_complete=checkpoint['source_complete'])
            outcome.password = _recover_transformed_wordlist(
                record, context, stream, checkpoint_path, checkpoint_identity, checkpoint, progress)
        finally:
            stream.close()
            generation = _combined_generation(base_generation, stream.stats)
            generation.update(
                generated_candidates=base_generated_candidates + stream.stats['eligible'],
                hashcat_confirmed_candidates=progress['hashcat_confirmed_candidates'],
                checkpointed_candidates=checkpoint['checkpointed_candidates'],
                confirmed_batches=checkpoint['confirmed_batches'])
            outcome.generation = generation
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
    print('  [Extraction] Reading authentication records...', flush=True)
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
                if not config.restart_incomplete:
                    for item in provenance['sources']:
                        storage.add_source(previous, item)
                    storage.atomic_json(previous_path, previous)
                store.clear(error)
                counts['skipped_' + previous['status']] += 1
                continue
            checkpoint_path, checkpoint_identity, checkpoint = None, None, None
            if wordlist_profile:
                checkpoint_identity = _checkpoint_identity(record, wordinfo, rules_info)
                checkpoint_path = store.checkpoint_path(record_id, attempt_key)
                if config.restart_incomplete:
                    backup = storage.backup_checkpoint_for_restart(checkpoint_path, checkpoint_identity)
                    if backup:
                        print(f'  Restarting incomplete attempt {record_id[:12]} '
                              f'(wordlist {wordinfo["sha256"][:12]}, profile {rules_info["sha256"][:12]}); '
                              f'previous checkpoint backed up to {backup}.', flush=True)
                checkpoint = storage.read_checkpoint(checkpoint_path, checkpoint_identity)
            print(f'\n  [Recovery] Attempt {record_id[:12]}: SSID={json.dumps(record["ssid"])} BSSID={record["bssid"]}', flush=True)
            attempt_started = time.monotonic()
            attempt_record(record, context, outcome, checkpoint_path,
                           checkpoint_identity, checkpoint)
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
    if config.status:
        try:
            config.validate()
            return checkpoint_status(config.output.resolve())
        except (OSError, ValueError) as exc:
            print(f'Cannot read status: {exc}', file=sys.stderr)
            return BatchResult(2)
    if config.estimate_only:
        try:
            config = config.normalized()
            prepared = candidates.PreparedCandidates(*candidates.select_profile(
                config.ssid, config.ssid_rules, config.rules, ROOT))
            if not prepared.wordlist_profile:
                raise ValueError('--estimate-only requires a transformed-wordlist profile')
            report_workload(config, prepared, config.wordlist)
            return BatchResult(0)
        except (OSError, ValueError, ToolError) as exc:
            print(f'Cannot estimate workload: {exc}', file=sys.stderr)
            return BatchResult(2)
    batch_started = time.monotonic()
    os.umask(0o077)
    counts = Counter()
    stats = RunStats()
    try:
        config = config.normalized()
        prepared = candidates.PreparedCandidates(*candidates.select_profile(
            config.ssid, config.ssid_rules, config.rules, ROOT))
        if config.restart_incomplete and (not prepared.wordlist_profile or config.check):
            raise ValueError('--restart-incomplete requires a transformed-wordlist recovery run')
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
            with (nullcontext(None) if config.check else BatchMonitor(runtime)) as monitor, \
                    tempfile.TemporaryDirectory(prefix='work-', dir=runtime) as directory:
                work = Path(directory).resolve()
                env = os.environ.copy()
                env.setdefault('RUSTICL_ENABLE', 'radeonsi')
                for variable, folder in [('XDG_DATA_HOME', 'data'), ('XDG_CACHE_HOME', 'cache')]:
                    location = runtime / folder
                    location.mkdir(exist_ok=True, mode=0o700)
                    env[variable] = str(location)
                env['POCL_CACHE_DIR'] = str(runtime / 'pocl-cache')
                env['PWNABASE_PROGRESS_INTERVAL'] = str(config.progress_interval)
                print('\n[Preparation] PMKID and EAPOL are captured authentication verification records; '
                      'wordlist exhaustion means no eligible candidate matched.\n', flush=True)
                print(f'Output: {config.output}; requested OpenCL device types: {config.device_types}', flush=True)
                wordlist, wordinfo, label = None, None, 'ssid'
                if not config.ssid and not config.check:
                    wordlist, wordinfo = candidates.snapshot_wordlist(config.wordlist, work)
                    label = wordinfo['label']
                if prepared.wordlist_profile and not config.check:
                    report_workload(config, prepared, wordlist)
                if config.rules and not config.ssid and not prepared.wordlist_profile:
                    native, info = candidates.load_rules(config.rules.resolve(), work)
                    prepared = replace(prepared, native_rules=native, rules_info=info)
                if monitor is not None:
                    mode = ('ssid' if config.ssid else 'wordlist-profile' if prepared.wordlist_profile
                            else 'native-rules' if prepared.native_rules else 'wordlist')
                    generator = (candidates.WORDLIST_GENERATOR if prepared.wordlist_profile else
                                 candidates.GENERATOR if config.ssid else None)
                    monitor.configure(mode, wordinfo, prepared.rules_info, generator)
                tool_config = tools.preflight(ToolConfig(config.hashcat, config.extractor,
                                                         config.device_types, prepared.native_rules), env, work)
                if config.ssid or prepared.wordlist_profile:
                    print(f'Generation profile: {prepared.rules_info["id"]}; fingerprint {prepared.rules_info["sha256"][:12]}; candidate generation limit 1,000,000 per seed.', flush=True)
                    if prepared.wordlist_profile:
                        print(f'Applying profile to wordlist entries in temporary candidate batches: '
                              f'up to {prepared.rules_info["maximum_generated"]:,} combinations per entry '
                              f'before deduplication. Initial batch target: {INITIAL_CANDIDATE_BATCH:,}; '
                              f'later batches target about {CANDIDATE_BATCH_TARGET_SECONDS}s total '
                              f'generation, file-writing, and Hashcat time (maximum '
                              f'{MAX_CANDIDATE_BATCH:,} candidates plus one source word).', flush=True)
                elif prepared.native_rules:
                    tools.validate_rules(tool_config, prepared.rules_info, env, work)
                else:
                    print('Rules: none; testing original wordlist entries only.', flush=True)
                if config.check:
                    return BatchResult(0, dict(counts), stats.records_seen, stats.captures_visited)
                monitor.update('running')
                if not config.handshakes.is_dir():
                    raise ToolError(f'Capture directory does not exist: {config.handshakes}')
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
                if counts['tool_error']:
                    monitor.update('failed')
                return BatchResult(1 if counts['tool_error'] else 0, dict(counts), stats.records_seen, stats.captures_visited)
    except KeyboardInterrupt:
        print('\nInterrupted. Completed results are saved. Transformed-wordlist attempts '
              'resume from their last confirmed checkpoint; other unfinished attempts restart.',
              file=sys.stderr)
        return BatchResult(130, dict(counts), stats.records_seen, stats.captures_visited)
    except (OSError, ValueError, ToolError, subprocess.TimeoutExpired) as exc:
        print(f'Cannot run batch: {exc}', file=sys.stderr)
        return BatchResult(2, dict(counts), stats.records_seen, stats.captures_visited)
