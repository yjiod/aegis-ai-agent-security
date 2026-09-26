"""Embedded reporting configuration: fixed destination, private atomic writes."""
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from urllib.parse import urlsplit

from aegis_macos_maintenance import MaintenanceError, directory


class ConfigurationError(Exception):
    """Fixed error code; never include input or filesystem details."""


def validate_config(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "report_url", "report_token", "signing_secret"}
            or value.get("schema") != "aegis.reporting/v1"):
        raise ConfigurationError("invalid_contract")
    url = value["report_url"]
    if not isinstance(url, str) or len(url) > 2048 or any(not 33 <= ord(c) <= 126 for c in url):
        raise ConfigurationError("invalid_url")
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or (parsed.port is not None and parsed.port < 1)):
            raise ValueError()
    except ValueError:
        raise ConfigurationError("invalid_url") from None
    token, secret = value["report_token"], value["signing_secret"]
    if any(not isinstance(item, str) or not 32 <= len(item) <= 4096
           or any(not 33 <= ord(c) <= 126 for c in item) for item in (token, secret)):
        raise ConfigurationError("invalid_credentials")
    if hmac.compare_digest(token, secret):
        raise ConfigurationError("independent_credentials_required")
    return dict(value)


def config_fingerprint(value):
    value = validate_config(value)
    payload = json.dumps({"schema": value["schema"], "report_url": value["report_url"],
                          "report_token": value["report_token"]}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(value["signing_secret"].encode(), b"aegis.reporting-receipt/v1\0" + payload,
                    hashlib.sha256).hexdigest()


def require_no_acl(fd):
    if sys.platform != "darwin":
        return
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.acl_get_fd_np.argtypes = (ctypes.c_int, ctypes.c_int)
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_free.argtypes = (ctypes.c_void_p,)
    libc.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED on Darwin
    if not acl:
        # The already-open descriptor exists; ENOENT means no extended ACL.
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise ConfigurationError("acl_unavailable")
    libc.acl_free(acl)
    # Do not silently reinterpret or remove administrator-defined ACLs.
    raise ConfigurationError("extended_acl_not_supported")


def require_private_file(fd, owner):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
            or info.st_mode & 0o077):
        raise ConfigurationError("unsafe_file")
    require_no_acl(fd)
    return info


def existing_state(parent, owner):
    try:
        fd = os.open("reporting.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        info = require_private_file(fd, owner)
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    finally:
        os.close(fd)


def write_config(root, value, owner=0):
    data = (json.dumps(validate_config(value), separators=(",", ":")) + "\n").encode()
    with directory(root) as parent:
        info = os.fstat(parent)
        if info.st_uid != owner or info.st_mode & 0o022:
            raise ConfigurationError("unsafe_install_directory")
        require_no_acl(parent)
        lock = os.open(".reporting-config.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=parent)
        try:
            require_private_file(lock, owner)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigurationError("configuration_busy") from None
            before = existing_state(parent, owner)
            name = ".reporting-config-" + secrets.token_hex(16) + ".tmp"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            committed = False
            try:
                with os.fdopen(fd, "wb") as stream:
                    require_private_file(stream.fileno(), owner)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if existing_state(parent, owner) != before:
                    raise ConfigurationError("configuration_changed")
                os.replace(name, "reporting.json", src_dir_fd=parent, dst_dir_fd=parent)
                committed = True
                try:
                    os.fsync(parent)
                except OSError:
                    return "applied_durability_unconfirmed"
                return "applied"
            finally:
                if not committed:
                    os.unlink(name, dir_fd=parent)
        finally:
            os.close(lock)


def selftest():
    value = {"schema": "aegis.reporting/v1", "report_url": "https://aegis.example.test/reports",
             "report_token": "synthetic-token-" * 4, "signing_secret": "synthetic-signing-" * 4}
    return (len(config_fingerprint(value)) == 64 and config_fingerprint(value)
            != config_fingerprint({**value, "report_token": "replacement-token-" * 4}))


def main(root):
    result = {"schema": "aegis.configuration-result/v1", "operation": "configure_reporting", "applied": False}
    code = 1
    try:
        if sys.platform != "darwin" or os.geteuid() != 0:
            raise ConfigurationError("administrator_required")
        override = os.environ.get("AEGIS_REPORT_CONFIG", "")
        if override and override != str(Path(root) / "reporting.json"):
            raise ConfigurationError("custom_destination_not_supported")
        value = {"schema": "aegis.reporting/v1", "report_url": os.environ.get("AEGIS_REPORT_URL", ""),
                 "report_token": os.environ.pop("AEGIS_REPORT_TOKEN", ""),
                 "signing_secret": os.environ.pop("AEGIS_REPORT_SIGNING_SECRET", "")}
        result["status"] = write_config(root, value)
        result["applied"] = True
        code = 0 if result["status"] == "applied" else 1
    except ConfigurationError as exc:
        result["status"] = str(exc)
    except (OSError, ValueError, MaintenanceError):
        result["status"] = "configuration_unavailable"
    print(json.dumps(result, separators=(",", ":")))
    return code
