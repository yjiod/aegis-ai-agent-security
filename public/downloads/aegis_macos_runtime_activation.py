"""Embedded native runtime replacement; this is not a full package transaction."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

from aegis_macos_configuration import read_private_json, require_no_acl, require_private_file
from aegis_macos_maintenance import LaunchServices, MaintenanceError, directory
from aegis_macos_service_migration import protected_directory

APP = Path("/Library/Application Support/AegisAgent")
JOURNAL = "native-runtime-activation.json"
BACKUP = ".native-runtime-previous"
CANONICAL = "aegis-agent"
SCHEMA = "aegis.native-runtime-activation/v1"
LIMIT = 128 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}")
STATUSES = {"preparing", "staged", "service_registered", "restoring", "restored_activation_pending"}


class ActivationError(ValueError):
    """Fixed status codes only; never include paths or file contents."""


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(parent, name, owner, limit=LIMIT, private=False, optional=False, allow_empty=False):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
                or info.st_mode & (0o077 if private else 0o022) or not 0 <= info.st_size <= limit
                or info.st_size == 0 and not allow_empty):
            raise ActivationError("unsafe_runtime_file")
        require_no_acl(stream.fileno())
        value = stream.read(limit + 1)
        if (len(value) != info.st_size or fingerprint(info) != fingerprint(os.fstat(stream.fileno()))
                or fingerprint(info) != fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))):
            raise ActivationError("runtime_file_changed")
        return value


def digest(value):
    return hashlib.sha256(value).hexdigest() if value is not None else None


def write(parent, name, data, mode=0o600):
    temporary = ".native-activation-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        replaced = True
        os.fsync(parent)
    finally:
        if not replaced:
            os.unlink(temporary, dir_fd=parent)


def save(parent, journal):
    write(parent, JOURNAL, (json.dumps(journal, separators=(",", ":")) + "\n").encode())


def valid_journal(value):
    return (isinstance(value, dict) and set(value) == {"schema", "status", "previous_sha256", "target_sha256", "target_version"}
            and value.get("schema") == SCHEMA and value.get("status") in STATUSES
            and isinstance(value.get("target_sha256"), str) and bool(DIGEST.fullmatch(value["target_sha256"]))
            and (value.get("previous_sha256") is None or isinstance(value["previous_sha256"], str)
                 and bool(DIGEST.fullmatch(value["previous_sha256"])))
            and isinstance(value.get("target_version"), str)
            and bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["target_version"])))


def marker_absent(parent):
    try:
        os.stat("watch-cleanup-pending.json", dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ActivationError("watch_cleanup_requires_verification")


def stopped(parent, services):
    # Stop both recognized system labels; do not replace a live executable merely
    # because bootout was attempted. Shared stop() confirms registration absence.
    marker_absent(parent)
    for label in ("com.aegis.agent", "com.company.aegis-agent"):
        services.stop("system", label)
    marker_absent(parent)


def change(app, services, mode, version, arch, owner=0):
    if mode not in {"stage", "confirm", "restore"} or arch not in {"arm64", "x86_64"}:
        raise ActivationError("invalid_activation_request")
    from aegis_macos_lifecycle import lease
    with lease(app, mode, owner), directory(app) as parent:
        protected_directory(parent, owner)
        lock = os.open(".native-runtime-activation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=parent)
        try:
            require_private_file(lock, owner)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ActivationError("runtime_activation_busy") from None
            return locked_change(Path(app), parent, services, mode, version, arch, owner)
        finally:
            os.close(lock)


def locked_change(app, parent, services, mode, version, arch, owner):
    try:
        journal = read_private_json(app / JOURNAL, owner)
    except FileNotFoundError:
        journal = None
    if journal is not None and not valid_journal(journal):
        raise ActivationError("activation_journal_invalid")
    current = read(parent, CANONICAL, owner, optional=True, allow_empty=True)
    current_sha = digest(current)
    if mode == "restore":
        if journal is None or journal["previous_sha256"] is None:
            raise ActivationError("previous_runtime_unavailable")
        if current_sha not in {journal["target_sha256"], journal["previous_sha256"]}:
            raise ActivationError("runtime_changed_recovery_required")
        backup = read(parent, BACKUP, owner, private=True, allow_empty=True)
        if digest(backup) != journal["previous_sha256"]:
            raise ActivationError("previous_runtime_integrity_failed")
        journal["status"] = "restoring"
        save(parent, journal)
        stopped(parent, services)
        if digest(read(parent, CANONICAL, owner, optional=True, allow_empty=True)) != current_sha:
            raise ActivationError("runtime_changed_recovery_required")
        write(parent, CANONICAL, backup, 0o755)
        journal["status"] = "restored_activation_pending"
        save(parent, journal)
        return journal["status"]
    artifact = "aegis-agent-darwin-" + ("arm64" if arch == "arm64" else "x64")
    manifest = json.loads(read(parent, "aegis-runtime-manifest.json", owner, limit=16384))
    candidate = read(parent, artifact, owner)
    target_sha = digest(candidate)
    if (not isinstance(manifest, dict) or manifest.get("schema") != "aegis.macos-runtime/v1"
            or manifest.get("agent_version") != version or not isinstance(manifest.get("files"), dict)
            or manifest["files"].get(artifact) != target_sha):
        raise ActivationError("candidate_integrity_failed")
    if mode == "confirm":
        if (journal is None or journal["status"] not in {"staged", "service_registered"}
                or journal["target_sha256"] != target_sha or journal["target_version"] != version
                or current_sha != target_sha):
            raise ActivationError("activation_not_staged")
        marker_absent(parent)
        if services.run(["print", "system/com.aegis.agent"]) != 0:
            raise ActivationError("service_registration_unconfirmed")
        if services.run(["print", "system/com.company.aegis-agent"]) != 113:
            raise ActivationError("legacy_service_registration_unconfirmed")
        journal["status"] = "service_registered"
        save(parent, journal)
        return journal["status"]
    pending = journal is not None and (journal["status"] in {"preparing", "staged", "restoring"}
        or journal["status"] == "service_registered" and current_sha == target_sha
        and journal["target_sha256"] == target_sha and journal["target_version"] == version)
    if pending:
        if (journal["status"] == "restoring" or journal["target_sha256"] != target_sha
                or journal["target_version"] != version
                or current_sha not in {journal["previous_sha256"], target_sha}):
            raise ActivationError("pending_activation_requires_recovery")
        # A crash after canonical replacement but before checkpoint is resumable
        # only with the exact retained backup and the same approved candidate.
        if current_sha == target_sha and journal["previous_sha256"] is not None:
            if digest(read(parent, BACKUP, owner, private=True, allow_empty=True)) != journal["previous_sha256"]:
                raise ActivationError("previous_runtime_integrity_failed")
    else:
        journal = {"schema": SCHEMA, "status": "preparing", "previous_sha256": current_sha,
                   "target_sha256": target_sha, "target_version": version}
        if not valid_journal(journal):
            raise ActivationError("invalid_activation_request")
        # Refuse an unsafe retained file even though replace() would not follow it.
        read(parent, BACKUP, owner, private=True, optional=True, allow_empty=True)
        save(parent, journal)
    stopped(parent, services)
    if digest(read(parent, CANONICAL, owner, optional=True, allow_empty=True)) != current_sha:
        raise ActivationError("runtime_changed_recovery_required")
    read(parent, BACKUP, owner, private=True, optional=True, allow_empty=True)
    if current_sha != target_sha or not pending:
        if current is not None:
            write(parent, BACKUP, current)
    if digest(read(parent, artifact, owner)) != target_sha:
        raise ActivationError("candidate_changed")
    if digest(read(parent, CANONICAL, owner, optional=True, allow_empty=True)) != current_sha:
        raise ActivationError("runtime_changed_recovery_required")
    write(parent, CANONICAL, candidate, 0o755)
    journal["status"] = "staged"
    save(parent, journal)
    return journal["status"]


def selftest():
    value = {"schema": SCHEMA, "status": "staged", "previous_sha256": None,
             "target_sha256": "a" * 64, "target_version": "1.2.3"}
    return valid_journal(value) and not valid_journal({**value, "status": "healthy"})


def main(app, mode, version):
    result = {"schema": "aegis.runtime-activation-result/v1", "health_verified": False}
    code = 1
    try:
        if Path(app) != APP:
            raise ActivationError("system_installation_required")
        if sys.platform != "darwin" or os.geteuid() != 0:
            raise ActivationError("administrator_required")
        result["status"] = change(app, LaunchServices(), mode, version, os.uname().machine)
        code = 0
    except (ActivationError, MaintenanceError) as exc:
        result["status"] = str(exc)
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        result["status"] = "activation_state_requires_verification"
    print(json.dumps(result, separators=(",", ":")))
    return code
