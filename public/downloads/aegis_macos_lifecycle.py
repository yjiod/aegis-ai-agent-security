"""Shared root maintenance lease, outside the runtime directory being replaced."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import secrets

from aegis_macos_configuration import read_private_json, require_no_acl, require_private_file
from aegis_macos_maintenance import MaintenanceError, directory

APP = Path('/Library/Application Support/AegisAgent')
LOCK = '.aegis-system-lifecycle.lock'
STATE = '.aegis-system-lifecycle.json'
SCHEMA = 'aegis.system-lifecycle/v1'
STATUSES = {'installing', 'ready', 'recovery_pending', 'uninstalling', 'uninstalled'}


class LifecycleError(MaintenanceError):
    """Fixed public status; no paths or state contents."""


def state(app, owner=0):
    try:
        value = read_private_json(Path(app).parent / STATE, owner)
    except FileNotFoundError:
        return None
    if (not isinstance(value, dict) or set(value) != {'schema', 'status'}
            or value.get('schema') != SCHEMA or not isinstance(value.get('status'), str)
            or value['status'] not in STATUSES):
        raise LifecycleError('maintenance_state_invalid')
    return value['status']


def save(parent, status):
    if status not in STATUSES:
        raise LifecycleError('maintenance_state_invalid')
    temporary = '.aegis-lifecycle-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    replaced = False
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps({'schema': SCHEMA, 'status': status}, separators=(',', ':')) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE, src_dir_fd=parent, dst_dir_fd=parent)
        replaced = True
        os.fsync(parent)
    finally:
        if not replaced:
            os.unlink(temporary, dir_fd=parent)


def protected_parent(parent, owner):
    info = os.fstat(parent)
    if info.st_uid != owner or info.st_mode & 0o022:
        raise LifecycleError('unsafe_maintenance_directory')
    require_no_acl(parent)


def ready_for_update(app, owner, current_state):
    if current_state not in (None, 'ready'):
        raise LifecycleError('maintenance_pending')
    with directory(app) as runtime:
        protected_parent(runtime, owner)
        try:
            os.stat('watch-cleanup-pending.json', dir_fd=runtime, follow_symlinks=False)
        except FileNotFoundError:
            cleanup_pending = False
        else:
            cleanup_pending = True
        if cleanup_pending:
            raise LifecycleError('watch_cleanup_requires_verification')
    # A previous client may have written an activation journal without this
    # shared state. Missing state is not permission to ignore that journal.
    from aegis_macos_runtime_activation import JOURNAL, valid_journal
    try:
        journal = read_private_json(Path(app) / JOURNAL, owner)
    except FileNotFoundError:
        return
    if not valid_journal(journal) or journal['status'] != 'service_registered':
        raise LifecycleError('activation_pending')


@contextlib.contextmanager
def lease(app, operation, owner=0):
    if operation not in {'stage', 'confirm', 'restore', 'uninstall', 'update'}:
        raise LifecycleError('maintenance_operation_invalid')
    app = Path(app)
    with directory(app.parent) as parent:
        protected_parent(parent, owner)
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        try:
            require_private_file(fd, owner)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LifecycleError('maintenance_busy') from None
            current = state(app, owner)
            if operation == 'update':
                ready_for_update(app, owner, current)
            elif operation != 'uninstall' and current == 'uninstalling':
                raise LifecycleError('uninstall_recovery_required')
            if operation in {'stage', 'restore', 'uninstall'}:
                save(parent, {'stage': 'installing', 'restore': 'recovery_pending', 'uninstall': 'uninstalling'}[operation])
            yield
            if operation in {'confirm', 'uninstall'}:
                save(parent, 'ready' if operation == 'confirm' else 'uninstalled')
        finally:
            os.close(fd)


def selftest():
    return len(STATUSES) == 5 and LOCK != STATE and APP.name == 'AegisAgent'
