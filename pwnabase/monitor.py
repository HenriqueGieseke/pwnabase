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
                      'state': 'starting', 'started_at': timestamp(), 'resumed_any': False}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker = None
        self.warned = False
        self.archive_enabled = False

    def update(self, state=None):
        with self.lock:
            if state is not None:
                self.state['state'] = state
            self.state['updated_at'] = timestamp()
            self._save()

    def _save(self):
        clear_dirty = False
        dirty = self.path.parent / 'batch-index-dirty'
        if 'configuration_id' in self.state and not self.archive_enabled:
            try:
                repair = dirty.exists()
                storage.atomic_json(dirty, {'needs_rebuild': True})
                self.archive_enabled = True
                index = (storage.rebuild_batch_index(self.path.parent) if repair
                         else storage.prepare_batch_index(self.path.parent))
                storage.append_batch_index(index, self.state)
                clear_dirty = True
            except (OSError, ValueError):
                pass  # The normal warning and future heartbeat retries cover this failure.
        paths = [self.path]
        if 'configuration_id' in self.state and self.archive_enabled:
            paths.append(self.runs / (self.state['run_id'] + '.json'))
        for path in paths:
            try:
                storage.atomic_json(path, self.state)
            except OSError:
                if not self.warned:
                    print('Batch status or history could not be saved; recovery continues.', file=sys.stderr)
                    self.warned = True
        if clear_dirty:
            try:
                dirty.unlink()
            except OSError:
                pass  # Leaving the marker in place forces a safe rebuild later.

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
            dirty = self.path.parent / 'batch-index-dirty'
            try:
                repair = dirty.exists()
                storage.atomic_json(dirty, {'needs_rebuild': True})
                self.archive_enabled = True
                index = (storage.rebuild_batch_index(self.path.parent) if repair
                         else storage.prepare_batch_index(self.path.parent))
                storage.append_batch_index(index, self.state)
                self._save()
                dirty.unlink()
            except (OSError, ValueError):
                if not self.warned:
                    print('Batch history index could not be saved; recovery continues.', file=sys.stderr)
                    self.warned = True
                self._save()

    def publish(self, **fields):
        with self.lock:
            self.state.update(fields)
            self.state['updated_at'] = timestamp()
            self._save()

    def add_execution_candidates(self, generated, confirmed, checkpointed):
        with self.lock:
            totals = self.state.setdefault('execution_candidates',
                                           {'generated': 0, 'confirmed': 0 if confirmed is not None else None,
                                            'checkpointed': 0 if checkpointed is not None else None})
            totals['generated'] += max(0, generated)
            for key, value in [('confirmed', confirmed), ('checkpointed', checkpointed)]:
                totals[key] = totals[key] + max(0, value) if totals[key] is not None and value is not None else None
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
        self.state['ended_at'] = timestamp()
        self.update(state)
        if state == 'failed':
            from .tools import ToolError
            category = ('tool' if isinstance(value, (ToolError, TimeoutError)) else
                        'filesystem' if isinstance(value, OSError) else
                        'input' if isinstance(value, ValueError) else 'unknown')
            self.event('batch_failed', category)
        else:
            self.event('batch_' + state)
