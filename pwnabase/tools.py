"""Run external tools with bounded diagnostic tails and candidate streaming.

run_tool returns (exit_code, diagnostic_tail). It propagates interrupts/timeouts
once the process group is stopped and workers are joined. A candidate source is
callable with a stop Event, yields byte chunks, and exposes seeds/eligible stats
when progress reporting is enabled. Producer failures raise ToolError; early
consumer closure is normal. Diagnostic text may contain secrets: callers must
filter it before logging and must not persist it.
Output is spooled to a temporary file; its disk usage is not capped.
"""

import json
import os
import signal
import subprocess
import tempfile
import threading
import time


class ToolError(Exception):
    """A tool or its candidate producer could not complete the operation."""


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
