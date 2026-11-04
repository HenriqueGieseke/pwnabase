"""Run external tools with bounded diagnostic tails and candidate streaming.

run_tool returns (exit_code, diagnostic_tail). It propagates interrupts/timeouts
once the process group is stopped and workers are joined. A candidate source is
callable with a stop Event, yields byte chunks, and exposes seeds/eligible stats
when progress reporting is enabled. Producer failures raise ToolError; early
consumer closure is normal. Diagnostic text may contain secrets: callers must
filter it before logging and must not persist it.
Output is spooled to a temporary file; its disk usage is not capped.
"""

from dataclasses import replace
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import shutil
import os
import signal
import subprocess
import tempfile
import threading
import time


class ToolError(Exception):
    """A tool or its candidate producer could not complete the operation."""


def run_tool(command, env, cwd, timeout=None, stdin_source=None, progress_callback=None):
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
        log_progress = interval > 0
        if progress_callback and interval <= 0:
            interval = 5
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
                    speeds = [d['speed'] for d in devices if isinstance(d, dict)
                              and isinstance(d.get('speed'), (int, float)) and math.isfinite(d['speed'])
                              and d['speed'] >= 0]
                    speed = sum(speeds) if speeds else None
                    remaining = (total - done) / speed if speed and total >= done and total > 0 and not stdin_source else None
                    if progress_callback and all(math.isfinite(value) and value >= 0 for value in (done, total)):
                        report = {'done': done, 'total': total}
                        if speed is not None and math.isfinite(speed):
                            report['speed'] = speed
                        if remaining is not None and math.isfinite(remaining):
                            report['eta_seconds'] = remaining
                        progress_callback(report)
                    rejected = latest.get('rejected')
                    rejected = rejected if isinstance(rejected, (int, float)) else 'unavailable'
                    eta = f'{remaining:.0f}s' if remaining is not None else 'unavailable'
                    if log_progress:
                        speed_text = f'{speed:.0f}' if speed is not None else 'unavailable'
                        print(f'  Progress {done}/{total}; {speed_text} H/s; '
                              f'rejected={rejected}; elapsed={time.monotonic() - started:.0f}s; estimated remaining={eta}', flush=True)
                elif log_progress:
                    print('  Hashcat running; waiting for its next progress report (startup may compile kernels).', flush=True)
                if stdin_source and log_progress:
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


def validate_rules(options, rules_info, env, work):
    probe = work / 'rule-validation.txt'
    probe.write_text('example123\n', encoding='ascii')
    code, diagnostic = run_tool([options.hashcat, '--stdout', '--quiet',
                                 '--wordlist-autohex-disable', '-r', str(options.native_rules), str(probe)],
                                env, work, timeout=30)
    if code or re.search(r'invalid[^\n]*rule|unsupported rule|no valid rules|cannot convert', diagnostic, re.IGNORECASE):
        raise ToolError('Hashcat rejected the rule catalog; check its expressions')
    print(f'Rules: {rules_info["id"]}; {len(rules_info["rules"])} independent transformations; '
          f'fingerprint {rules_info["sha256"][:12]}', flush=True)


def recover(record, wordlist, options, env, work, use_rules=True, hex_wordlist=False, candidate_stream=None,
            progress_callback=None):
    hashes, recovered = work / 'input.22000', work / 'recovered.hex'
    hashes.write_text(record['hashcat_record'] + '\n', encoding='ascii')
    recovered.unlink(missing_ok=True)
    command = [options.hashcat, '-m', '22000', '-a', '0', '-D', options.device_types,
               '-w', '1', '--quiet', '--status', '--status-json', '--status-timer',
               str(max(1, int(env.get('PWNABASE_PROGRESS_INTERVAL', '10')))), '--potfile-disable', '--restore-disable',
               '--logfile-disable', '--wordlist-autohex-disable',
               '--session', 'pwnabase', '--outfile-format', '3',
               '--outfile', str(recovered), str(hashes)]
    if candidate_stream is None:
        command.append(str(wordlist))
    if use_rules and options.native_rules:
        command.extend(['-r', str(options.native_rules)])
    if hex_wordlist:
        command.append('--hex-wordlist')
    if candidate_stream is not None:
        command.append('--stdin-timeout-abort=0')
    if candidate_stream is None:
        code, diagnostic = (run_tool(command, env, work, progress_callback=progress_callback)
                            if progress_callback else run_tool(command, env, work))
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


def preflight(options, env, work):
    print('Checking dependencies and testing mode 22000 recovery (first run may compile kernels)...', flush=True)
    binaries = {}
    for name in ('hashcat', 'extractor'):
        binary = shutil.which(getattr(options, name))
        if not binary:
            raise ToolError(f'Missing {getattr(options, name)}; install hashcat and hcxtools')
        binaries[name] = str(Path(binary).resolve())
    options = replace(options, **binaries)
    for binary in (options.hashcat, options.extractor):
        code, _ = run_tool([binary, '--version'], env, work, timeout=30)
        print(f'{Path(binary).name}: {_.strip()}', flush=True)
        if code:
            raise ToolError(f'{Path(binary).name} version check failed (exit {code})')
    code, backend = run_tool([options.hashcat, '-I'], env, work, timeout=30)
    if code:
        raise ToolError(f'Compute device enumeration failed (exit {code})')
    for line in backend.splitlines():
        if line.strip().startswith(('Type.', 'Name.')):
            print('  Available backend: ' + json.dumps(line.strip()), flush=True)
    # Backend enumeration alone does not prove kernels can run. Verify a known PMKID.
    words = work / 'self-test.txt'
    words.write_bytes(b'testpass123\n')
    try:
        password = recover(parse_record(synthetic_record()), words, options, env, work, use_rules=False)
    except ToolError as exc:
        raise ToolError(f'Hashcat mode 22000 self-test failed: {exc}. '
                        'Inspect devices with hashcat -I; try --device-types 1 for CPU testing') from exc
    if password != b'testpass123':
        raise ToolError('Hashcat backend self-test failed')
    print('Dependencies and mode 22000 recovery verified.', flush=True)
    return options


def extract_capture(snapshot, extractor, env, work):
    extracted = work / 'extracted.22000'
    extracted.unlink(missing_ok=True)
    code, diagnostic = run_tool([extractor, '-o', str(extracted), str(snapshot)],
                                env, work)
    # Some converter failures are reported in output despite a zero exit status.
    if code or re.search(r'failed to|read error|invalid (?:pcap|capture)|unsupported (?:pcap|link)',
                         diagnostic, re.IGNORECASE):
        raise ToolError(f'hcxpcapngtool could not read capture (exit {code})')
    lines = extracted.read_text(encoding='ascii').splitlines() if extracted.exists() else []
    records = {record['record_id']: record for line in lines if line.strip()
               for record in [parse_record(line.strip())]}
    return records
