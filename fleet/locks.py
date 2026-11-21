"""One exclusive write lock per firewall, shared by every workflow that changes a device.

Rule deploys, definition and alias syncs, VIP changes and firmware requests all
take the same lock, so one workflow's preflight ("device unchanged since the
snapshot") cannot be invalidated by another workflow writing at the same time.
The lock is an flock() on a file in the data directory, so it serializes
Gunicorn threads and workers on one host that share OPNMANAGER_DATA_DIR.
"""

import fcntl
import os
from contextlib import contextmanager

from django.conf import settings

from .opnsense_errors import DeviceError


def lock_path(firewall_pk):
    return settings.DATA_DIR / f".device-write-{firewall_pk}.lock"


@contextmanager
def device_write_lock(firewall_pk, operation):
    """Hold the firewall's write lock or raise DeviceError naming the operation already running."""
    with open(lock_path(firewall_pk), "a+", opener=lambda p, flags: os.open(p, flags, 0o600)) as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock.seek(0)
            holder = lock.read().strip() or "Another device change"
            raise DeviceError(
                f"{holder} is already running for this firewall. Review again after it completes."
            ) from exc
        try:
            lock.seek(0)
            lock.truncate()
            lock.write(operation)
            lock.flush()
            yield
        finally:
            lock.truncate(0)
            fcntl.flock(lock, fcntl.LOCK_UN)
