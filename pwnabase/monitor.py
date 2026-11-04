"""Private, bounded lifecycle telemetry for a local recovery batch."""

from datetime import datetime, timezone
import hashlib
import json
import sys
import threading
import uuid

from . import storage


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class BatchMonitor:
    def __init__(self, runtime):
        self.path = runtime / 'batch-status.json'
        self.runs = runtime / 'batch-runs'
        self.events = runtime / 'batch-events'
        self.state = {'schema_version': 1, 'run_id': uuid.uuid4().hex,
                      'state': 'starting', 'started_at': timestamp()}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker = None
        self.warned = False

    def update(self, state=None):
        with self.lock:
            if state is not None:
                self.state['state'] = state
            self.state['updated_at'] = timestamp()
            self._save()

    def _save(self):
        paths = [self.path]
        if 'configuration_id' in self.state:
            paths.append(self.runs / (self.state['run_id'] + '.json'))
        for path in paths:
            try:
                storage.atomic_json(path, self.state)
            except OSError:
                if not self.warned:
                    print('Batch status or history could not be saved; recovery continues.', file=sys.stderr)
                    self.warned = True

    def configure(self, mode, wordinfo, rules_info, generator):
        identity = {'mode': mode, 'wordlist': wordinfo['sha256'] if wordinfo else None,
                    'rules': rules_info['sha256'] if rules_info else None,
                    'generator': generator}
        digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        label = (wordinfo['label'] if wordinfo else 'SSID')[:128]
        rule_label = rules_info.get('id', '')[:128] if rules_info else None
        with self.lock:
            self.state.update(configuration_id=digest, source_label=label,
                              mode=mode, rule_label=rule_label)
            self.state['updated_at'] = timestamp()
            self._save()

    def publish(self, **fields):
        with self.lock:
            self.state.update(fields)
            self.state['updated_at'] = timestamp()
            self._save()

    def event(self, kind, category=None):
        allowed = {'batch_started', 'batch_running', 'batch_completed', 'batch_interrupted',
                   'batch_failed', 'capture_started', 'capture_unusable', 'capture_skipped',
                   'record_recovered', 'record_exhausted', 'record_skipped', 'record_failed',
                   'capture_failed', 'checkpoint_saved'}
        if kind not in allowed:
            raise ValueError('Unsupported batch event')
        with self.lock:
            event = {'kind': kind, 'at': timestamp()}
            if category in {'tool', 'input', 'filesystem', 'unknown'}:
                event['category'] = category
            for key in ('capture_name', 'ssid', 'bssid'):
                value = self.state.get(key)
                if isinstance(value, str):
                    event[key] = value[:512]
            try:
                storage.append_event(self.events, self.state['run_id'], event)
            except OSError:
                if not self.warned:
                    print('Batch status or history could not be saved; recovery continues.', file=sys.stderr)
                    self.warned = True

    def __enter__(self):
        self.update('starting')
        self.event('batch_started')
        def heartbeat():
            while not self.stop.wait(5):
                self.update()
        self.worker = threading.Thread(target=heartbeat, daemon=True)
        self.worker.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.stop.set()
        self.worker.join()
        if kind is KeyboardInterrupt:
            state = 'interrupted'
        elif kind is not None or self.state['state'] == 'failed':
            state = 'failed'
        else:
            state = 'completed'
        self.update(state)
        if state == 'failed':
            from .tools import ToolError
            category = ('tool' if isinstance(value, (ToolError, TimeoutError)) else
                        'filesystem' if isinstance(value, OSError) else
                        'input' if isinstance(value, ValueError) else 'unknown')
            self.event('batch_failed', category)
        else:
            self.event('batch_' + state)
