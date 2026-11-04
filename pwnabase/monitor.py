"""Private, bounded lifecycle telemetry for a local recovery batch."""

from datetime import datetime, timezone
import sys
import threading
import uuid

from . import storage


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class BatchMonitor:
    def __init__(self, runtime):
        self.path = runtime / 'batch-status.json'
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
            try:
                storage.atomic_json(self.path, self.state)
            except OSError:
                if not self.warned:
                    print('Batch status could not be saved; recovery continues.', file=sys.stderr)
                    self.warned = True

    def __enter__(self):
        self.update('starting')
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
