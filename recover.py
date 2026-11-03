#!/usr/bin/env python3
"""Local batch recovery of authorized WPA/WPA2 captures. Python 3.10+."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import signal
import threading
import time
import subprocess
import sys
import tempfile

from ssid_candidates import (load_profile, generate as generate_ssid,
                             source_info as ssid_source, WordlistCandidates, WORDLIST_GENERATOR)


ROOT = Path(__file__).resolve().parent
EXTENSIONS = {'.pcap', '.pcapng', '.cap'}


class ToolError(Exception):
    pass


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


def run_tool(command, env, cwd, timeout=None, stdin_source=None):
    # A separate process group lets Ctrl+C stop the tool and any workers.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(command, stdin=subprocess.PIPE if stdin_source else subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, env=env, cwd=cwd,
                                   start_new_session=True)
        stop = threading.Event()
        feed_errors = []
        def feed():
            try:
                for chunk in stdin_source(stop):
                    if stop.is_set():
                        break
                    process.stdin.write(chunk)
            except BrokenPipeError:
                pass  # Expected when Hashcat recovers a password before EOF.
            except Exception as error:
                feed_errors.append(error)
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
        interval = float(env.get('PWNABASE_PROGRESS_INTERVAL', '0'))
        def progress():
            position = 0
            pending = ""
            while not stop.wait(interval):
                raw = os.pread(output.fileno(), 65536, position)
                position += len(raw)
                latest = None
                pending += raw.decode('utf-8', errors='replace')
                lines = pending.split('\n')
                pending = lines.pop()[-65536:]
                for line in lines:
                    try:
                        value = json.loads(line)
                        if isinstance(value, dict) and isinstance(value.get('progress'), list) and len(value['progress']) == 2 and all(isinstance(n, (int, float)) for n in value['progress']):
                            latest = value
                    except (ValueError, TypeError):
                        pass
                if latest:
                    done, total = latest.get('progress', [0, 0])[:2]
                    devices = latest.get('devices')
                    devices = devices if isinstance(devices, list) else []
                    speed = sum(d.get('speed', 0) for d in devices if isinstance(d, dict) and isinstance(d.get('speed', 0), (int, float)))
                    remaining = (total - done) / speed if speed and total >= done and total > 0 and not stdin_source else None
                    rejected = latest.get('rejected')
                    rejected = rejected if isinstance(rejected, (int, float)) else 'unavailable'
                    eta = f'{remaining:.0f}s' if remaining is not None else 'unavailable'
                    print(f'  Progress {done}/{total}; {speed:.0f} H/s; '
                          f'rejected={rejected}; elapsed={time.monotonic() - started:.0f}s; estimated remaining={eta}', flush=True)
                else:
                    print('  Hashcat running; waiting for its next progress report (startup may compile kernels).', flush=True)
                if stdin_source:
                    print(f'  Wordlist generation: {stdin_source.stats["seeds"]} seeds; '
                          f'{stdin_source.stats["eligible"]} eligible candidates generated (per-seed deduplication).', flush=True)
        started = time.monotonic()
        worker = None
        if interval > 0 and '-m' in command:
            worker = threading.Thread(target=progress, daemon=True)
            worker.start()
        feeder = None
        if stdin_source:
            feeder = threading.Thread(target=feed, daemon=True)
            feeder.start()
        try:
            code = process.wait(timeout=timeout)
        except (KeyboardInterrupt, subprocess.TimeoutExpired):
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
        finally:
            stop.set()
            if worker:
                worker.join()
            if feeder:
                feeder.join()
        if feed_errors:
            raise ToolError(f'Candidate generation failed: {type(feed_errors[0]).__name__}')
        output.seek(max(0, output.seek(0, 2) - 65536))
        # Never persist tool output: it can include password candidates.
        return code, output.read().decode('utf-8', errors='replace')


def parse_record(line):
    fields = line.split('*')
    if len(fields) != 9 or fields[0] != 'WPA' or fields[1] not in {'01', '02'}:
        raise ToolError('Extractor produced an unsupported authentication record')
    try:
        for field in fields[2:]:
            bytes.fromhex(field)
        if len(fields[2]) != 32 or any(len(fields[i]) != 12 for i in (3, 4)):
            raise ValueError()
        ssid = bytes.fromhex(fields[5])
        if not 1 <= len(ssid) <= 32:
            raise ValueError()
    except ValueError as exc:
        raise ToolError('Extractor produced malformed authentication material') from exc
    canonical = 'WPA*' + '*'.join(field.lower() for field in fields[1:])
    return {
        'record_id': hashlib.sha256(canonical.encode('ascii')).hexdigest(),
        'hashcat_record': canonical,
        'kind': 'pmkid' if fields[1] == '01' else 'eapol',
        'bssid': ':'.join(fields[3][i:i + 2] for i in range(0, 12, 2)).lower(),
        'client_mac': ':'.join(fields[4][i:i + 2] for i in range(0, 12, 2)).lower(),
        'ssid': ssid.decode('utf-8', errors='replace'),
        'ssid_hex': ssid.hex(),
    }


def synthetic_record(password=b'testpass123', ssid=b'pwnabase-self-test'):
    ap, client = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    pmk = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    pmkid = hmac.new(pmk, b'PMK Name' + ap + client, hashlib.sha1).digest()[:16]
    return f'WPA*01*{pmkid.hex()}*{ap.hex()}*{client.hex()}*{ssid.hex()}***'


def load_rules(path, work):
    catalog = read_json(path)
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


def validate_rules(args, env, work):
    probe = work / 'rule-validation.txt'
    probe.write_text('example123\n', encoding='ascii')
    code, diagnostic = run_tool([args.hashcat, '--stdout', '--quiet',
                                 '--wordlist-autohex-disable', '-r', str(args.native_rules), str(probe)],
                                env, work, timeout=30)
    if code or re.search(r'invalid[^\n]*rule|unsupported rule|no valid rules|cannot convert', diagnostic, re.IGNORECASE):
        raise ToolError('Hashcat rejected the rule catalog; check its expressions')
    print(f'Rules: {args.rules_info["id"]}; {len(args.rules_info["rules"])} independent transformations; '
          f'fingerprint {args.rules_info["sha256"][:12]}', flush=True)


def recover(record, wordlist, args, env, work, use_rules=True, hex_wordlist=False, candidate_stream=None):
    hashes, recovered = work / 'input.22000', work / 'recovered.hex'
    hashes.write_text(record['hashcat_record'] + '\n', encoding='ascii')
    recovered.unlink(missing_ok=True)
    command = [args.hashcat, '-m', '22000', '-a', '0', '-D', args.device_types,
               '-w', '1', '--quiet', '--status', '--status-json', '--status-timer',
               str(max(1, int(env.get('PWNABASE_PROGRESS_INTERVAL', '10')))), '--potfile-disable', '--restore-disable',
               '--logfile-disable', '--wordlist-autohex-disable',
               '--session', 'pwnabase', '--outfile-format', '3',
               '--outfile', str(recovered), str(hashes)]
    if candidate_stream is None:
        command.append(str(wordlist))
    if use_rules and getattr(args, 'native_rules', None):
        command.extend(['-r', str(args.native_rules)])
    if hex_wordlist:
        command.append('--hex-wordlist')
    if candidate_stream is not None:
        command.append('--stdin-timeout-abort=0')
    if candidate_stream is None:
        code, diagnostic = run_tool(command, env, work)
    else:
        code, diagnostic = run_tool(command, env, work, stdin_source=candidate_stream)
    if code not in (0, 1):
        reasons = {'No devices found': 'no compatible compute devices found', 'No hashes loaded': 'no compatible authentication records loaded', 'CL_OUT_OF_RESOURCES': 'compute device ran out of resources', 'CL_MEM_OBJECT_ALLOCATION_FAILURE': 'compute memory allocation failed', 'Signature unmatched': 'authentication record signature rejected'}
        reason = next((message for marker, message in reasons.items() if marker in diagnostic), 'tool failed without a recognized diagnostic')
        raise ToolError(f'Hashcat recovery failed (exit {code}): {reason}; verify input format and compute backend with --check')
    if candidate_stream and code == 1 and not candidate_stream.stats['source_complete']:
        raise ToolError('Hashcat stopped before candidate generation completed; attempt is not exhausted')
    if recovered.exists() and recovered.stat().st_size:
        try:
            values = recovered.read_text(encoding='ascii').splitlines()
            if len(values) != 1:
                raise ValueError()
            password = bytes.fromhex(values[0])
        except (ValueError, UnicodeError) as exc:
            raise ToolError('Hashcat produced an invalid password output') from exc
        return password
    if code == 0:
        raise ToolError('Hashcat reported recovery without a password output')
    return None


def preflight(args, env, work):
    print('Checking dependencies and testing mode 22000 recovery (first run may compile kernels)...', flush=True)
    for name in ('hashcat', 'extractor'):
        binary = shutil.which(getattr(args, name))
        if not binary:
            raise ToolError(f'Missing {getattr(args, name)}; install hashcat and hcxtools')
        setattr(args, name, str(Path(binary).resolve()))
    for binary in (args.hashcat, args.extractor):
        code, _ = run_tool([binary, '--version'], env, work, timeout=30)
        print(f'{Path(binary).name}: {_.strip()}', flush=True)
        if code:
            raise ToolError(f'{Path(binary).name} version check failed (exit {code})')
    code, backend = run_tool([args.hashcat, '-I'], env, work, timeout=30)
    if code:
        raise ToolError(f'Compute device enumeration failed (exit {code})')
    for line in backend.splitlines():
        if line.strip().startswith(('Type.', 'Name.')):
            print('  Available backend: ' + json.dumps(line.strip()), flush=True)
    # Backend enumeration alone does not prove kernels can run. Verify a known PMKID.
    words = work / 'self-test.txt'
    words.write_bytes(b'testpass123\n')
    try:
        password = recover(parse_record(synthetic_record()), words, args, env, work, use_rules=False)
    except ToolError as exc:
        raise ToolError(f'Hashcat mode 22000 self-test failed: {exc}. '
                        'Inspect devices with hashcat -I; try --device-types 1 for CPU testing') from exc
    if password != b'testpass123':
        raise ToolError('Hashcat backend self-test failed')
    print('Dependencies and mode 22000 recovery verified.', flush=True)


def add_source(result, source):
    sources = result.setdefault('sources', [])
    if source not in sources:
        sources.append(source)


def result_base(status, source, wordlist, rules=None):
    return {'schema_version': 1, 'status': status,
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'sources': [source], 'wordlist': wordlist, 'rules': rules}


def process_capture(path, args, env, work, wordlist, wordinfo, counts):
    # Work on a byte-for-byte snapshot; never modify or clean original packets.
    snapshot = work / ('capture' + path.suffix.lower())
    shutil.copyfile(path, snapshot)
    capture_id = fingerprint(snapshot)
    source = {'path': str(path), 'sha256': capture_id}
    no_usable = args.output / 'no-usable-handshake' / f'{capture_id}.json'
    state = args.output / '.pwnabase' / 'captures' / f'{capture_id}.json'
    previous = read_json(no_usable)
    if previous and not args.retry_unusable:
        print('  Skipped: unchanged capture previously yielded no usable handshake.', flush=True)
        add_source(previous, source)
        atomic_json(no_usable, previous)
        counts['skipped_unusable'] += 1
        return
    print('  Extracting authentication records...', flush=True)
    extracted = work / 'extracted.22000'
    extracted.unlink(missing_ok=True)
    code, diagnostic = run_tool([args.extractor, '-o', str(extracted), str(snapshot)],
                                env, work)
    # Some converter failures are reported in output despite a zero exit status.
    if code or re.search(r'failed to|read error|invalid (?:pcap|capture)|unsupported (?:pcap|link)',
                         diagnostic, re.IGNORECASE):
        raise ToolError(f'hcxpcapngtool could not read capture (exit {code})')
    lines = extracted.read_text(encoding='ascii').splitlines() if extracted.exists() else []
    records = {record['record_id']: record for line in lines if line.strip()
               for record in [parse_record(line.strip())]}
    args.records_seen = getattr(args, 'records_seen', 0) + len(records)
    print(f'  Extracted {len(records)} records: ' + str(dict(Counter(r["kind"] for r in records.values()))), flush=True)
    provenance = read_json(state) or {'schema_version': 1, 'sources': []}
    add_source(provenance, source)
    provenance['records'] = list(records.values())
    atomic_json(state, provenance)
    if not records:
        result = result_base('no_usable_handshake', source, None)
        result['sources'] = provenance['sources']
        atomic_json(no_usable, result)
        print(f'  No usable handshake; saved {no_usable}', flush=True)
        counts['no_usable_handshake'] += 1
        return
    no_usable.unlink(missing_ok=True)
    for record_id, record in records.items():
        success = args.output / 'complete' / f'{record_id}.json'
        rules_info = getattr(args, 'rules_info', None)
        ssid_mode = getattr(args, 'ssid', False)
        wordlist_profile = getattr(args, 'wordlist_profile', False)
        candidate_source = ssid_source(bytes.fromhex(record['ssid_hex'])) if ssid_mode else dict(type='wordlist', **wordinfo)
        if wordlist_profile:
            candidate_source.update(transformation='ssid_profile', generator=WORDLIST_GENERATOR)
        attempt_key = (('ssid-' if ssid_mode else WORDLIST_GENERATOR + '-' if wordlist_profile else '') + candidate_source['sha256']
                       + ('-' + rules_info['sha256'] if rules_info else ''))
        label = 'ssid' if ssid_mode else wordinfo['label']
        exhausted = args.output / 'exhausted' / label / f'{record_id}-{attempt_key}.json'
        error = args.output / 'tool-error' / f'record-{record_id}.json'
        generation = None
        try:
            # Content identity survives renaming a wordlist or its parent folder.
            matches = sorted((args.output / 'exhausted').glob(
                f'*/{record_id}-{attempt_key}.json'))
            previous_path = success if success.exists() else (matches[0] if matches else exhausted)
            previous = read_json(previous_path)
            if previous:
                print(f'  Skipped {record_id[:12]}: {previous["status"]} (matching saved result).', flush=True)
                for item in provenance['sources']:
                    add_source(previous, item)
                atomic_json(previous_path, previous)
                error.unlink(missing_ok=True)
                counts['skipped_' + previous['status']] += 1
                continue
            print(f'  Attempting {record_id[:12]}: SSID={json.dumps(record["ssid"])} BSSID={record["bssid"]}', flush=True)
            attempt_started = time.monotonic()
            if ssid_mode:
                candidates, generation = generate_ssid(bytes.fromhex(record['ssid_hex']), args.ssid_config)
                print('  SSID candidate counts: ' + json.dumps(generation, sort_keys=True), flush=True)
                if not generation['valid_utf8']:
                    print('  SSID is not valid UTF-8; testing exact bytes only, without text transformations.', flush=True)
                candidate_file = work / 'ssid-candidates.hex'
                with candidate_file.open('w', encoding='ascii') as stream:
                    for candidate in candidates:
                        stream.write(candidate.hex() + '\n')
                password = recover(record, candidate_file, args, env, work, use_rules=False, hex_wordlist=True) if candidates else None
                status = ('recovered' if password is not None else
                          'candidates_exhausted' if candidates else 'no_eligible_candidates')
            elif wordlist_profile:
                stream = WordlistCandidates(wordlist, args.ssid_config)
                try:
                    password = recover(record, None, args, env, work, use_rules=False,
                                       hex_wordlist=True, candidate_stream=stream)
                finally:
                    generation = dict(stream.stats)
                    print('  Wordlist profile counts: ' + json.dumps(generation, sort_keys=True), flush=True)
                status = ('recovered' if password is not None else
                          'no_eligible_candidates' if not generation['eligible'] else 'wordlist_exhausted')
            else:
                password = recover(record, wordlist, args, env, work)
                status = 'recovered' if password is not None else 'wordlist_exhausted'
            result = result_base(status, source, wordinfo, rules_info)
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
            atomic_json(success if password is not None else exhausted, result)
            error.unlink(missing_ok=True)
            print(f'  {status}: {time.monotonic() - attempt_started:.1f}s; saved {success if password is not None else exhausted}', flush=True)
            counts[status] += 1
        except (OSError, ValueError, ToolError) as exc:
            result = result_base('tool_error', source, wordinfo, getattr(args, 'rules_info', None))
            result['candidate_source'] = candidate_source
            if generation is not None:
                result['candidate_generation'] = generation
            result.update(record=record, error=str(exc))
            atomic_json(error, result)
            counts['tool_error'] += 1
            print(f'  Record {record_id[:12]}: {exc}; continuing with remaining inputs.', file=sys.stderr, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
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
    if args.progress_interval < 0:
        parser.error('--progress-interval must be nonnegative')
    if args.preview_limit < 1:
        parser.error('--preview-limit must be positive')
    if args.preview_ssid is not None and args.check:
        parser.error('--preview-ssid and --check cannot be combined')
    args.ssid = args.ssid or args.preview_ssid is not None
    if args.ssid and args.ssid_rules:
        parser.error('--ssid-rules is a wordlist option; do not combine it with --ssid or --preview-ssid')
    if not args.ssid:
        args.wordlist = (args.wordlist or ROOT / 'SambaTu' / 'SambaTu.txt').resolve()
    batch_started = time.monotonic()
    os.umask(0o077)
    args.output = args.output.resolve()
    args.handshakes = args.handshakes.resolve()
    counts = Counter()
    try:
        selected_catalog = read_json(args.rules.resolve()) if args.rules and not args.ssid else None
        args.wordlist_profile = args.ssid_rules or bool(
            isinstance(selected_catalog, dict) and selected_catalog.get('type') == 'ssid_profile')
        if args.ssid or args.wordlist_profile:
            args.rules_info, args.ssid_config = load_profile((args.rules or ROOT / 'rules' / 'ssid.json').resolve())
        if args.preview_ssid is not None:
            seed = args.preview_ssid.encode('utf-8')
            if not 1 <= len(seed) <= 32:
                raise ToolError('Preview SSID must contain 1–32 UTF-8 bytes')
            candidates, stats = generate_ssid(seed, args.ssid_config)
            print('SSID preview counts: ' + json.dumps(stats, sort_keys=True))
            limit = min(len(candidates), args.preview_limit)
            print(f'Sample of {limit} eligible candidates out of {len(candidates)} (no captures read, no recovery):')
            for index in range(limit):
                print(json.dumps(candidates[index * len(candidates) // limit].decode('utf-8'), ensure_ascii=False))
            return 0
        runtime = args.output / '.pwnabase'
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
                env['PWNABASE_PROGRESS_INTERVAL'] = str(args.progress_interval)
                print('PMKID and EAPOL are captured authentication verification records; wordlist exhaustion means no eligible candidate matched.', flush=True)
                print(f'Output: {args.output}; requested OpenCL device types: {args.device_types}', flush=True)
                args.native_rules = None
                if not args.ssid and not args.wordlist_profile:
                    args.rules_info = None
                if args.rules and not args.ssid and not args.wordlist_profile:
                    args.native_rules, args.rules_info = load_rules(args.rules.resolve(), work)
                preflight(args, env, work)
                if args.ssid or args.wordlist_profile:
                    print(f'Generation profile: {args.rules_info["id"]}; fingerprint {args.rules_info["sha256"][:12]}; candidate generation limit 1,000,000 per seed.', flush=True)
                    if args.wordlist_profile:
                        print(f'Applying profile to wordlist entries via streaming stdin: up to {args.rules_info["maximum_generated"]:,} combinations per entry before deduplication. Total count and ETA are unavailable; this can substantially increase runtime.', flush=True)
                elif args.native_rules:
                    validate_rules(args, env, work)
                else:
                    print('Rules: none; testing original wordlist entries only.', flush=True)
                if args.check:
                    return 0
                if not args.handshakes.is_dir():
                    raise ToolError(f'Capture directory does not exist: {args.handshakes}')
                wordlist, wordinfo, label = None, None, 'ssid'
                if not args.ssid:
                    wordlist = work / 'wordlist.txt'
                    shutil.copyfile(args.wordlist, wordlist)
                    if not wordlist.stat().st_size:
                        raise ToolError('Wordlist is empty')
                    label = re.sub(r'[^A-Za-z0-9._-]', '_', args.wordlist.stem).strip('.') or 'wordlist'
                    wordinfo = {'path': str(args.wordlist), 'label': label, 'sha256': fingerprint(wordlist)}
                for folder in ['complete', f'exhausted/{label}', 'no-usable-handshake', 'tool-error']:
                    (args.output / folder).mkdir(parents=True, exist_ok=True, mode=0o700)
                captures = sorted(p for p in args.handshakes.iterdir()
                                  if p.is_file() and p.suffix.lower() in EXTENSIONS)
                print(f'Found {len(captures)} captures; source: {"each record’s SSID" if args.ssid else args.wordlist.name}.', flush=True)
                for index, path in enumerate(captures, 1):
                    print(f'[{index}/{len(captures)}] {path.name}', flush=True)
                    try:
                        process_capture(path, args, env, work, wordlist, wordinfo, counts)
                    except (OSError, ValueError, ToolError) as exc:
                        # Path identity also works for files that cannot be opened/fingerprinted.
                        error_id = hashlib.sha256(str(path).encode()).hexdigest()
                        source = {'path': str(path)}
                        try:
                            source['sha256'] = fingerprint(path)
                        except OSError:
                            pass
                        result = result_base('tool_error', source, wordinfo, getattr(args, 'rules_info', None))
                        result['candidate_source'] = dict(type='ssid', label='SSID') if args.ssid else dict(type='wordlist', **(wordinfo or {}))
                        result['error'] = str(exc)
                        atomic_json(args.output / 'tool-error' / f'path-{error_id}.json', result)
                        counts['tool_error'] += 1
                        print(f'  Capture error: {exc}; continuing with remaining inputs.', file=sys.stderr, flush=True)
                    else:
                        error_id = hashlib.sha256(str(path).encode()).hexdigest()
                        (args.output / 'tool-error' / f'path-{error_id}.json').unlink(missing_ok=True)
                print(f'Batch elapsed: {time.monotonic() - batch_started:.1f}s; captures visited: {len(captures)}', flush=True)
                print(f'Authentication records encountered: {getattr(args, "records_seen", 0)} (including duplicates across captures).', flush=True)
                for label, key in [('Recovered records', 'recovered'), ('Exhausted wordlist records', 'wordlist_exhausted'), ('Exhausted SSID records', 'candidates_exhausted'), ('No eligible candidates', 'no_eligible_candidates'), ('Unusable captures', 'no_usable_handshake'), ('Skipped recovered records', 'skipped_recovered'), ('Skipped exhausted wordlist records', 'skipped_wordlist_exhausted'), ('Skipped exhausted SSID records', 'skipped_candidates_exhausted'), ('Skipped no-eligible-candidate records', 'skipped_no_eligible_candidates'), ('Skipped unusable captures', 'skipped_unusable'), ('Capture or record errors', 'tool_error')]:
                    print(f'  {label}: {counts[key]}', flush=True)
                print('Summary: ' + json.dumps(dict(counts), sort_keys=True), flush=True)
                return 1 if counts['tool_error'] else 0
    except KeyboardInterrupt:
        print('\nInterrupted. Completed results are saved; unfinished attempts will restart.', file=sys.stderr)
        return 130
    except (OSError, ValueError, ToolError, subprocess.TimeoutExpired) as exc:
        print(f'Cannot run batch: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
