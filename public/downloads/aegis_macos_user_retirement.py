"""Retire only the calling user's recognized legacy launch files; retain data."""
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

from aegis_macos_configuration import require_private_file
from aegis_macos_maintenance import AGENT_LABELS, LaunchServices, MaintenanceError, directory, save_journal
from aegis_macos_service_migration import MigrationError, exclusive_rename, protected_directory, snapshot

ARCHIVE = "AegisLegacyRetirement"


def pending(home):
    marker = home / "Library/Application Support/AegisAgent/watch-cleanup-pending.json"
    if marker.exists() or marker.is_symlink():
        raise MaintenanceError("watch_cleanup_requires_verification")


def retire(home, uid, services):
    """Internal filesystem seam for synthetic tests; CLI never accepts a home/uid."""
    home = Path(home)
    with directory(home) as fd:
        info = os.fstat(fd)
        if info.st_uid != uid or info.st_mode & 0o022:
            raise MaintenanceError("unsafe_user_home")
    support = home / "Library/Application Support"
    launch = home / "Library/LaunchAgents"
    pending(home)
    items = []
    try:
        with directory(launch) as source:
            protected_directory(source, uid)
            for label in AGENT_LABELS:
                name = label + ".plist"
                before = snapshot(source, name, uid)
                if before is not None:
                    items.append({"name": name, "before": before, "stage": "planned"})
    except FileNotFoundError:
        items = []  # No launch directory; loaded jobs are still checked below.
    with directory(support) as parent:
        protected_directory(parent, uid)
        try:
            os.mkdir(ARCHIVE, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            if not stat.S_ISDIR(os.stat(ARCHIVE, dir_fd=parent, follow_symlinks=False).st_mode):
                raise MaintenanceError("unsafe_user_archive")
    with directory(support / ARCHIVE) as root:
        protected_directory(root, uid)
        if stat.S_IMODE(os.fstat(root).st_mode) != 0o700:
            raise MaintenanceError("unsafe_user_archive")
        lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=root)
        try:
            require_private_file(lock, uid)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MaintenanceError("user_retirement_busy") from None
            return locked_retire(home, launch, root, items, uid, services)
        finally:
            os.close(lock)


def locked_retire(home, launch, root, items, uid, services):
    batch = secrets.token_hex(16)
    os.mkdir(batch, 0o700, dir_fd=root)
    os.fsync(root)
    archive = os.open(batch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    try:
        protected_directory(archive, uid)
        record = {"schema": "aegis.user-retirement/v1", "status": "partial", "items": items,
                  "scope": "current_user", "runtime_retained": True, "baselines_retained": True}

        def checkpoint():
            save_journal(archive, record)
            os.fsync(archive)

        checkpoint()
        pending(home)
        # Stop only these domains. No system service, another uid or arbitrary
        # plist contents can supply a target. Missing files do not imply no job.
        for domain in ("gui/" + str(uid), "user/" + str(uid)):
            for label in AGENT_LABELS:
                services.stop(domain, label)
        pending(home)
        for item in items:
            with directory(launch) as source:
                protected_directory(source, uid)
                if snapshot(source, item["name"], uid) != item["before"]:
                    raise MaintenanceError("legacy_plist_changed")
                exclusive_rename(source, item["name"], item["name"], destination_parent=archive)
                os.fsync(source)
                os.fsync(archive)
                after = snapshot(archive, item["name"], uid)
                if after is None or after[:4] != item["before"][:4]:
                    raise MaintenanceError("legacy_plist_changed_after_move")
                item.update(stage="archived", after=after)
            checkpoint()
        # A concurrent re-created launch file invalidates the completed claim.
        try:
            with directory(launch) as source:
                protected_directory(source, uid)
                if any(snapshot(source, label + ".plist", uid) is not None for label in AGENT_LABELS):
                    raise MaintenanceError("legacy_source_recreated")
        except FileNotFoundError:
            if items:
                raise MaintenanceError("legacy_launch_directory_disappeared") from None
            record["launch_directory_present"] = False
        for domain in ("gui/" + str(uid), "user/" + str(uid)):
            code = services.run(["print", domain])
            if code == 112:
                continue
            if code != 0:
                raise MaintenanceError("service_domain_unavailable")
            for label in AGENT_LABELS:
                if services.run(["print", domain + "/" + label]) != 113:
                    raise MaintenanceError("service_absence_unconfirmed")
        pending(home)
        record["status"] = "retired_with_retained_state"
        checkpoint()
        return {"status": record["status"], "archived_launch_files": len(items)}
    finally:
        os.close(archive)


def selftest():
    return ARCHIVE == "AegisLegacyRetirement" and AGENT_LABELS == ("com.aegis.agent", "com.company.aegis-agent")


def main():
    result = {"schema": "aegis.user-retirement-result/v1", "scope": "current_user",
              "runtime_retained": True, "baselines_retained": True, "health_verified": False}
    try:
        uid = os.getuid()
        if sys.platform != "darwin" or uid == 0 or os.geteuid() != uid:
            result["status"] = "unprivileged_macos_user_required"
            print(json.dumps(result, sort_keys=True))
            return 2
        import pwd
        # HOME, SUDO_USER and arbitrary path overrides never select the account.
        home = Path(pwd.getpwuid(uid).pw_dir)
        if not home.is_absolute() or home.parent != Path("/Users") or home.name.startswith("."):
            raise MaintenanceError("unsupported_user_home")
        result.update(retire(home, uid, LaunchServices()))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, MaintenanceError, subprocess.SubprocessError) as error:
        result.update(status="incomplete", reason=str(error) if isinstance(error, (MaintenanceError, MigrationError))
                      else "user_retirement_io_or_service_error")
        print(json.dumps(result, sort_keys=True))
        return 1
