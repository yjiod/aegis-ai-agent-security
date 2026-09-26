#!/usr/bin/env python3
"""macOS uninstall. No network, credential parsing or quarantine restoration."""
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

START = b"<!-- aegis-managed-user-baseline:start -->"
END = b"<!-- aegis-managed-user-baseline:end -->"
BASELINES = (".codex/AGENTS.md", ".claude/CLAUDE.md", ".workbuddy/AGENTS.md",
             ".qwenworkcn/AGENTS.md", ".gemini/GEMINI.md", ".copilot/copilot-instructions.md",
             ".lingma/rules.md", ".codebuddy/rules.md")
AGENT_LABELS = ("com.aegis.agent", "com.company.aegis-agent")
SYSTEM_LABELS = AGENT_LABELS + ("com.aegis.execguard",)
MAX_BASELINE_BYTES = 2 * 1024 * 1024


class MaintenanceError(Exception):
    """Fixed diagnostic code without user content or a filesystem path."""


@contextlib.contextmanager
def directory(path):
    """Open every component without following links, including ancestors."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise MaintenanceError("unsafe_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def strip_managed_block(data):
    """Remove one standalone block; preserve every other byte exactly."""
    if START not in data and END not in data:
        return data
    if data.count(START) != 1 or data.count(END) != 1:
        raise MaintenanceError("malformed_baseline_markers")
    lines = data.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == START]
    ends = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == END]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise MaintenanceError("malformed_baseline_markers")
    return b"".join(lines[:starts[0]] + lines[ends[0] + 1:])


def copy_metadata(source, destination, info):
    if sys.platform == "darwin":
        # Darwin copyfile.h: COPYFILE_ACL | COPYFILE_STAT | COPYFILE_XATTR = 7.
        # Use descriptors, never reopen a potentially replaced source path.
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.fcopyfile.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        libc.fcopyfile.restype = ctypes.c_int
        if libc.fcopyfile(source, destination, None, 7) != 0:
            raise MaintenanceError("baseline_metadata_copy_failed")
    else:  # Portable regression tests; production CLI is macOS-only.
        if os.geteuid() == 0:
            os.fchown(destination, info.st_uid, info.st_gid)
        os.fchmod(destination, stat.S_IMODE(info.st_mode))


def clean_baseline(home, relative):
    if relative not in BASELINES:
        raise MaintenanceError("baseline_target_not_allowed")
    home = Path(home)
    with contextlib.ExitStack() as stack:
        try:
            home_fd = stack.enter_context(directory(home))
            parent = stack.enter_context(directory(home / Path(relative).parent))
            owner = os.fstat(home_fd).st_uid
            if os.fstat(parent).st_uid != owner:
                raise MaintenanceError("baseline_directory_owner_mismatch")
            fd = os.open(Path(relative).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stream = stack.enter_context(os.fdopen(fd, "rb"))
        except FileNotFoundError:
            return False
        return _clean_open_baseline(parent, Path(relative).name, stream, owner)


def _clean_open_baseline(parent, name, stream, owner):
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != owner:
        raise MaintenanceError("unsafe_baseline_file")
    data = stream.read(MAX_BASELINE_BYTES + 1)
    if len(data) > MAX_BASELINE_BYTES:
        raise MaintenanceError("baseline_too_large")
    updated = strip_managed_block(data)
    if updated == data:
        return False
    temporary = ".aegis-uninstall-" + secrets.token_hex(12)
    new_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        with os.fdopen(new_fd, "wb") as output:
            output.write(updated)
            output.flush()
            copy_metadata(stream.fileno(), output.fileno(), info)
            os.fsync(output.fileno())
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size) != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size):
            raise MaintenanceError("baseline_changed_during_cleanup")
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
    return True


class LaunchServices:
    def __init__(self, run=None):
        self.run = run or self._run

    @staticmethod
    def _run(arguments):
        return subprocess.run(["/bin/launchctl", *arguments], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=15, check=False).returncode

    def stop(self, domain, label):
        if not re.fullmatch(r"system|(?:gui|user)/[0-9]+", domain) or not re.fullmatch(r"[A-Za-z0-9.-]+", label):
            raise MaintenanceError("invalid_service_identifier")
        domain_result = self.run(["print", domain])
        if domain_result == 112 and domain != "system":  # launchctl: domain not found
            return
        if domain_result != 0:
            raise MaintenanceError("service_domain_unavailable")
        target = domain + "/" + label
        before = self.run(["print", target])
        if before == 113:  # service not found in the available domain
            return
        if before != 0:
            raise MaintenanceError("service_status_unknown")
        if self.run(["bootout", target]) != 0:
            raise MaintenanceError("service_stop_failed")
        for _ in range(10):
            result = self.run(["print", target])
            if result == 113:
                return
            if result != 0:
                raise MaintenanceError("service_stop_unconfirmed")
            time.sleep(0.2)
        raise MaintenanceError("service_still_registered")


def archive_item(source, archive_fd, name, owner):
    """Move without reading contents or following links. Cross-volume moves fail."""
    source = Path(source)
    try:
        with directory(source.parent) as parent:
            info = os.stat(source.name, dir_fd=parent, follow_symlinks=False)
            if info.st_uid != owner or stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise MaintenanceError("unsafe_archive_source")
            os.rename(source.name, name, src_dir_fd=parent, dst_dir_fd=archive_fd)
            return True
    except FileNotFoundError:
        return False


def save_journal(archive, journal):
    temporary = ".status-" + secrets.token_hex(8)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=archive)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(journal, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, "status.json", src_dir_fd=archive, dst_dir_fd=archive)
    finally:
        try:
            os.unlink(temporary, dir_fd=archive)
        except FileNotFoundError:
            pass


def uninstall(app, daemon_dir, homes, archive_parent, services):
    from aegis_macos_lifecycle import lease
    with lease(app, "uninstall", os.geteuid()):
        return _uninstall_locked(app, daemon_dir, homes, archive_parent, services)


def _uninstall_locked(app, daemon_dir, homes, archive_parent, services):
    """Stop every service before editing user files or moving any runtime."""
    for label in SYSTEM_LABELS:
        services.stop("system", label)
    for home in homes:
        with directory(home) as fd:
            uid = os.fstat(fd).st_uid
        for domain in ("gui/" + str(uid), "user/" + str(uid)):
            for label in AGENT_LABELS:
                services.stop(domain, label)
    runtimes=[Path(app)]+[Path(home)/"Library/Application Support/AegisAgent" for home in homes]
    for runtime in runtimes:
        marker=runtime/"watch-cleanup-pending.json"
        if marker.exists() or marker.is_symlink():
            raise MaintenanceError("watch_cleanup_requires_verification")
    with directory(archive_parent) as parent:
        try:
            os.mkdir("AegisUninstallArchive", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        root_path = Path(archive_parent) / "AegisUninstallArchive"
        with directory(root_path) as archive_root:
            info = os.fstat(archive_root)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise MaintenanceError("unsafe_archive_directory")
            if sys.platform == "darwin":
                # A 0700 mode alone does not remove inherited macOS ACL grants.
                # This verified directory is owned by the calling administrator.
                subprocess.run(["/bin/chmod", "-N", str(root_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            archive_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(8)
            os.mkdir(archive_id, 0o700, dir_fd=archive_root)
        with directory(root_path / archive_id) as archive:
            journal = {"schema": "aegis.uninstall/v1", "status": "partial", "cleaned_baselines": 0,
                       "retained_quarantine": True, "restored_blocked_assets": False, "archived_items": 0}
            save_journal(archive, journal)
            for home in homes:
                for relative in BASELINES:
                    if clean_baseline(home, relative):
                        journal["cleaned_baselines"] += 1
                        save_journal(archive, journal)

            def retain(source, name, owner):
                if archive_item(source, archive, name, owner):
                    journal["archived_items"] += 1
                    save_journal(archive, journal)

            for label in SYSTEM_LABELS:
                retain(Path(daemon_dir) / (label + ".plist"), label + ".plist", os.geteuid())
            for home in homes:
                with directory(home) as fd:
                    uid = os.fstat(fd).st_uid
                key = hashlib.sha256(str(home).encode()).hexdigest()[:16]
                for label in AGENT_LABELS:
                    for suffix in (".plist", ".plist.disabled-by-system-install"):
                        retain(Path(home) / "Library/LaunchAgents" / (label + suffix), key + "-" + label + suffix, uid)
                retain(Path(home) / "Library/Application Support/AegisAgent", key + "-runtime", uid)
            retain(app, "system-runtime", os.geteuid())
            journal.update(status="uninstalled_with_retained_state")
            save_journal(archive, journal)
            return journal


def selftest():
    """Pure, side-effect-free check also embedded in the frozen client."""
    return strip_managed_block(b"personal\n" + START + b"\nmanaged\n" + END + b"\n") == b"personal\n"


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args == ["--selftest"]:
        if not selftest():
            return 1
        print("aegis-maintenance-selftest-ok")
        return 0
    if args or sys.platform != "darwin" or os.geteuid() != 0:
        print("Aegis uninstall requires macOS, administrator privileges and no arguments", file=sys.stderr)
        return 2
    try:
        homes = [Path("/private/var/root")]
        with directory("/Users") as users:
            with os.scandir(users) as entries:
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    if entry.is_symlink():
                        raise MaintenanceError("linked_home_requires_review")
                    if entry.is_dir(follow_symlinks=False):
                        homes.append(Path("/Users") / entry.name)
        result = uninstall(Path("/Library/Application Support/AegisAgent"), Path("/Library/LaunchDaemons"),
                           sorted(homes), Path("/Library/Application Support"), LaunchServices())
        print(json.dumps(result, sort_keys=True))
        print("Repository rule files and quarantined assets remain unchanged.")
        return 0
    except (OSError, MaintenanceError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, MaintenanceError) else "maintenance_io_or_service_error"
        print(json.dumps({"status": "incomplete", "reason": reason, "retained_state": True}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
