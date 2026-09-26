"""Publish an allowlisted, identity-free desktop view of system diagnostics."""
import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
import time

from aegis_macos_configuration import require_no_acl
from aegis_macos_maintenance import directory

APP = Path('/Library/Application Support/AegisAgent')
NAME = 'desktop-status.json'
SCHEMA = 'aegis.desktop-status/v1'
REFRESH_SECONDS = 60
CHECKS = {'installed': 'AegisInstalled', 'integrity': 'AegisIntegrityValid',
          'service': 'AegisLaunchDaemonHealthy', 'configured': 'AegisReportingConfigured',
          'reporting': 'AegisReportingHealthy', 'report_valid': 'AegisReportValid', 'scan_recent': 'AegisScanRecent'}
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,32})?')


def snapshot(health, version, now=None):
    if not isinstance(health, dict) or not isinstance(version, str) or len(version) > 64 or not VERSION.fullmatch(version):
        raise ValueError('invalid_desktop_status')
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or not 0 <= observed <= 253402300799:
        raise ValueError('invalid_desktop_timestamp')
    policy = health.get('AegisPolicyVersion')
    if not isinstance(policy, str) or len(policy) > 64 or not VERSION.fullmatch(policy):
        policy = 'unknown'
    return {'schema': SCHEMA, 'agent_version': version, 'policy_version': policy, 'observed_at': observed,
            'checks': {name: health.get(source) is True for name, source in CHECKS.items()}}


def publish(app, value, owner=0):
    # Reconstruct the public contract rather than serializing caller-supplied data.
    if (not isinstance(value, dict) or set(value) != {'schema', 'agent_version', 'policy_version', 'observed_at', 'checks'}
            or value.get('schema') != SCHEMA or not isinstance(value.get('checks'), dict)
            or set(value['checks']) != set(CHECKS) or any(type(flag) is not bool for flag in value['checks'].values())):
        raise ValueError('invalid_desktop_contract')
    health = {source: value['checks'][name] for name, source in CHECKS.items()}
    health['AegisPolicyVersion'] = value['policy_version']
    clean = snapshot(health, value['agent_version'], value['observed_at'])
    data = (json.dumps(clean, separators=(',', ':')) + '\n').encode()
    if len(data) > 4096:
        raise ValueError('desktop_status_too_large')
    with directory(app) as parent:
        info = os.fstat(parent)
        if info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('unsafe_desktop_directory')
        require_no_acl(parent)
        try:
            existing = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            try:
                old = os.fstat(existing)
                if not stat.S_ISREG(old.st_mode) or old.st_nlink != 1 or old.st_uid != owner or old.st_mode & 0o022:
                    raise ValueError('unsafe_desktop_file')
                require_no_acl(existing)
            finally:
                os.close(existing)
        name = '.desktop-status-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        replaced = False
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)  # Public contract contains no identity or findings.
                os.fsync(stream.fileno())
            os.replace(name, NAME, src_dir_fd=parent, dst_dir_fd=parent)
            replaced = True
            os.fsync(parent)
        finally:
            if not replaced:
                os.unlink(name, dir_fd=parent)


@contextlib.contextmanager
def watch(app, version, validate_policy):
    # Only the installed frozen system watch parent may publish. Development
    # scans, maintenance commands and one-shot children do not create snapshots.
    if (sys.platform != 'darwin' or os.geteuid() != 0 or not getattr(sys, 'frozen', False)
            or Path(app) != APP or Path(sys.executable) != APP / 'aegis-agent'):
        yield
        return
    from aegis_macos_diagnostics import collect
    stop = threading.Event()

    def refresh():
        while not stop.is_set():
            try:
                value = snapshot(collect(app, version, validate_policy), version)
                if not stop.is_set():
                    publish(app, value)
            except Exception:
                # A failure leaves the old snapshot to expire. No raw exception,
                # report contents or credentials enter UI or this log message.
                print('aegis desktop status unavailable', file=sys.stderr)
            stop.wait(REFRESH_SECONDS)

    # Diagnostics cannot delay the scanner watchdog's signal handling or budget.
    worker = threading.Thread(target=refresh, name='aegis-desktop-status', daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join(timeout=0.2)


def selftest():
    value = snapshot({'AegisInstalled': True, 'AegisPolicyVersion': '1.2.3', 'private': 'not exported'}, '1.2.3', 1)
    return set(value) == {'schema', 'agent_version', 'policy_version', 'observed_at', 'checks'} and len(value['checks']) == 7
