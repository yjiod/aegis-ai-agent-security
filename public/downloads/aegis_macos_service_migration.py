"""Reversible legacy LaunchAgent preparation; never read credential contents."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from aegis_macos_configuration import read_private_json, require_no_acl, require_private_file
from aegis_macos_maintenance import AGENT_LABELS, LaunchServices, MaintenanceError, directory

JOURNAL = "legacy-service-migration.json"
SUFFIX = ".disabled-by-system-install"
MAX_HOMES = 64


class MigrationError(ValueError):
    """Fixed public status only."""


def snapshot(parent, name, owner):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner
                or info.st_mode & 0o022):
            raise MigrationError("unsafe_legacy_plist")
        require_no_acl(fd)
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    finally:
        os.close(fd)


def protected_directory(fd, owner):
    info = os.fstat(fd)
    if info.st_uid != owner or info.st_mode & 0o022:
        raise MigrationError("unsafe_migration_directory")
    require_no_acl(fd)


def save(parent, value):
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    if len(data) > 32768:
        raise MigrationError("migration_journal_too_large")
    temporary = ".legacy-migration-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, JOURNAL, src_dir_fd=parent, dst_dir_fd=parent)
        replaced = True
        os.fsync(parent)
    finally:
        if not replaced:
            os.unlink(temporary, dir_fd=parent)


def collect(homes):
    if len(homes) > MAX_HOMES:
        raise MigrationError("migration_home_limit")
    result = {}
    for home in homes:
        home = Path(home)
        with directory(home) as fd:
            uid = os.fstat(fd).st_uid
        key = hashlib.sha256(str(home).encode()).hexdigest()
        if key in result:
            raise MigrationError("duplicate_migration_home")
        result[key] = (home / "Library/LaunchAgents", uid, home / "Library/Application Support/AegisAgent/watch-cleanup-pending.json")
    return result


def change(app, homes, services, restore=False, owner=0):
    """Journal before stop/rename; partial work always requires explicit recovery."""
    app = Path(app)
    locations = collect(homes)
    with directory(app) as parent:
        protected_directory(parent, owner)
        lock = os.open(".legacy-service-migration.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=parent)
        try:
            require_private_file(lock, owner)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("migration_busy") from None
            return locked_change(app, parent, locations, services, restore, owner)
        finally:
            os.close(lock)


def locked_change(app, parent, locations, services, restore, owner):
    try:
        previous = read_private_json(app / JOURNAL, owner)
    except FileNotFoundError:
        previous = None
    if previous is not None:
        if (not isinstance(previous, dict) or previous.get("schema") != "aegis.legacy-services/v1"
                or previous.get("status") not in ({"prepared", "preparing", "restoring", "restored_activation_pending"} if restore else {"prepared"})
                or not isinstance(previous.get("items"), list)):
            raise MigrationError("migration_recovery_required")
        items = previous["items"]
    elif restore:
        raise MigrationError("migration_journal_required")
    else:
        items = []
        for key, (path, uid, marker) in locations.items():
            try:
                with directory(path) as source:
                    protected_directory(source, uid)
                    for label in AGENT_LABELS:
                        name = label + ".plist"
                        if snapshot(source, name + SUFFIX, uid) is not None:
                            raise MigrationError("untracked_legacy_backup")
                        before = snapshot(source, name, uid)
                        if before is not None:
                            items.append({"home": key, "label": label, "before": before, "stage": "planned"})
            except FileNotFoundError:
                continue
    if len(items) > MAX_HOMES * len(AGENT_LABELS):
        raise MigrationError("invalid_migration_journal")
    if not items and previous is None:
        return {"status": "no_legacy_services", "items": 0}
    # Validate every item before stopping any service or moving a plist.
    seen = set()
    for item in items:
        if (not isinstance(item, dict) or item.get("home") not in locations or item.get("label") not in AGENT_LABELS
                or item.get("stage") not in {"planned", "retired", "restored"}
                or (item["home"], item["label"]) in seen):
            raise MigrationError("invalid_migration_journal")
        seen.add((item["home"], item["label"]))
        path, uid, marker = locations[item["home"]]
        if marker.exists() or marker.is_symlink():
            raise MigrationError("watch_cleanup_requires_verification")
        name = item["label"] + ".plist"
        with directory(path) as source:
            protected_directory(source, uid)
            retired = item["stage"] == "retired"
            current = snapshot(source, name + SUFFIX if retired else name, uid)
            expected = item.get("before" if item["stage"] == "planned" else "after")
            if current is None or current != expected:
                raise MigrationError("legacy_plist_changed")
            if snapshot(source, name if retired else name + SUFFIX, uid) is not None:
                raise MigrationError("legacy_source_recreated")
    if previous:
        for key, (path, uid, _) in locations.items():
            try:
                with directory(path) as source:
                    protected_directory(source, uid)
                    for label in AGENT_LABELS:
                        if (key, label) not in seen and (snapshot(source, label + ".plist", uid) is not None
                                or snapshot(source, label + ".plist" + SUFFIX, uid) is not None):
                            raise MigrationError("untracked_legacy_service")
            except FileNotFoundError:
                continue
    if restore:
        # Never revive user configuration while the system service is registered.
        if services.run(["print", "system/com.aegis.agent"]) != 113:
            raise MigrationError("system_service_must_be_absent")
    journal = {"schema": "aegis.legacy-services/v1", "status": "restoring" if restore else "preparing", "items": items}
    save(parent, journal)
    for item in ([] if restore else items):
        path, uid, marker = locations[item["home"]]
        for domain in ("gui/" + str(uid), "user/" + str(uid)):
            services.stop(domain, item["label"])
        if marker.exists() or marker.is_symlink():
            raise MigrationError("watch_cleanup_requires_verification")
    for item in items:
        if (restore and item["stage"] != "retired") or (not restore and item["stage"] == "retired"):
            continue
        path, uid, _ = locations[item["home"]]
        name = item["label"] + ".plist"
        src, dst = (name + SUFFIX, name) if restore else (name, name + SUFFIX)
        with directory(path) as source:
            protected_directory(source, uid)
            if snapshot(source, src, uid) != item.get("after" if restore else "before"):
                raise MigrationError("legacy_plist_changed")
            # Atomic no-replace rename on Darwin; never overwrite an existing backup.
            exclusive_rename(source, src, dst)
            os.fsync(source)
            after = snapshot(source, dst, uid)
            before = item.get("after" if restore else "before")
            if after is None or after[:4] != before[:4]:
                raise MigrationError("legacy_plist_changed_after_move")
            item["after"] = after
            item["stage"] = "restored" if restore else "retired"
        save(parent, journal)
    journal["status"] = "restored_activation_pending" if restore else "prepared"
    save(parent, journal)
    return {"status": journal["status"], "items": len(items)}


def exclusive_rename(parent, source, destination):
    import ctypes
    if sys.platform != "darwin":
        raise MigrationError("macos_required")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.renameatx_np.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    libc.renameatx_np.restype = ctypes.c_int
    if libc.renameatx_np(parent, os.fsencode(source), parent, os.fsencode(destination), 4) != 0:  # RENAME_EXCL
        raise MigrationError("legacy_rename_failed")


def selftest():
    return len(AGENT_LABELS) == 2 and SUFFIX.startswith(".") and MAX_HOMES == 64


def main(app, restore=False):
    result = {"schema": "aegis.service-migration-result/v1", "health_verified": False}
    code = 1
    try:
        if sys.platform != "darwin" or os.geteuid() != 0:
            raise MigrationError("administrator_required")
        with os.scandir("/Users") as entries:
            homes = [Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False)]
        result.update(change(app, homes, LaunchServices(), restore=restore))
        code = 0
    except (MigrationError, MaintenanceError) as exc:
        result["status"] = str(exc)
    except (OSError, ValueError, TypeError):
        result["status"] = "migration_state_requires_verification"
    print(json.dumps(result, separators=(",", ":")))
    return code
