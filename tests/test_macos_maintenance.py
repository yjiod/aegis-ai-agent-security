"""Synthetic state only. Optional live test uses an isolated user launchd job."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("maintenance", ROOT / "public/downloads/aegis_macos_maintenance.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-maintenance-tests-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.app = self.root / "AegisAgent"
        self.app.mkdir()
        self.daemons = self.root / "LaunchDaemons"
        self.daemons.mkdir()
        self.data = b"personal\r\n\n" + m.START + b"\nfixture baseline\n" + m.END + b"\ntrailing-no-newline"
        self.expected = b"personal\r\n\ntrailing-no-newline"

    def baseline(self, relative=m.BASELINES[0], data=None):
        p = self.home / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(self.data if data is None else data)
        p.chmod(0o640)
        return p

    def uninstall(self, services=None):
        return m.uninstall(self.app, self.daemons, [self.home], self.root,
                           services or m.LaunchServices(lambda args: 0 if args[1] in ("system", "gui/" + str(os.geteuid()), "user/" + str(os.geteuid())) else 113))

    def test_eight_baselines_preserve_personal_bytes_mode_and_ownership(self):
        for relative in m.BASELINES:
            p = self.baseline(relative)
            before = p.stat()
            self.assertTrue(m.clean_baseline(self.home, relative))
            self.assertEqual(p.read_bytes(), self.expected)
            self.assertEqual(p.stat().st_mode, before.st_mode)
            self.assertEqual(p.stat().st_uid, before.st_uid)
            self.assertEqual(p.stat().st_gid, before.st_gid)
            self.assertFalse(m.clean_baseline(self.home, relative))

    def test_absent_or_unmanaged_file_is_not_created_or_changed(self):
        self.assertFalse(m.clean_baseline(self.home, m.BASELINES[0]))
        p = self.baseline(data=b"untouched\xff")
        inode = p.stat().st_ino
        self.assertFalse(m.clean_baseline(self.home, m.BASELINES[0]))
        self.assertEqual(p.stat().st_ino, inode)
        self.assertEqual(p.read_bytes(), b"untouched\xff")

    def test_malformed_markers_fail_without_modification(self):
        for data in (m.START, m.END, m.END + b"\n" + m.START, self.data + m.START,
                     b"prefix" + m.START + b"\n" + m.END, m.START + b"\n" + m.END + b"suffix"):
            with self.subTest(data_length=len(data)):
                p = self.baseline(data=data)
                with self.assertRaises(m.MaintenanceError):
                    m.clean_baseline(self.home, m.BASELINES[0])
                self.assertEqual(p.read_bytes(), data)

    def test_symlink_and_hardlink_targets_are_refused(self):
        outside = self.root / "unmanaged"
        outside.write_bytes(self.data)
        p = self.baseline()
        p.unlink()
        p.symlink_to(outside)
        with self.assertRaises(OSError):
            m.clean_baseline(self.home, m.BASELINES[0])
        p.unlink()
        os.link(outside, p)
        with self.assertRaises(m.MaintenanceError):
            m.clean_baseline(self.home, m.BASELINES[0])
        self.assertEqual(outside.read_bytes(), self.data)

    def test_symlinked_parent_is_refused(self):
        outside = self.root / "unmanaged-dir"
        outside.mkdir()
        (outside / "AGENTS.md").write_bytes(self.data)
        (self.home / ".codex").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            m.clean_baseline(self.home, m.BASELINES[0])
        self.assertEqual((outside / "AGENTS.md").read_bytes(), self.data)

    def test_fifo_is_refused_without_blocking(self):
        p = self.baseline()
        p.unlink()
        os.mkfifo(p)
        with self.assertRaises(m.MaintenanceError):
            m.clean_baseline(self.home, m.BASELINES[0])

    def test_unknown_and_oversized_targets_fail(self):
        with self.assertRaises(m.MaintenanceError):
            m.clean_baseline(self.home, "../AGENTS.md")
        self.baseline(data=b"x" * (m.MAX_BASELINE_BYTES + 1))
        with self.assertRaises(m.MaintenanceError):
            m.clean_baseline(self.home, m.BASELINES[0])

    def test_concurrent_edit_is_retained(self):
        p = self.baseline()
        copy = m.copy_metadata
        def concurrent(source, destination, info):
            copy(source, destination, info)
            p.write_bytes(b"user edited during cleanup")
        with patch.object(m, "copy_metadata", side_effect=concurrent):
            with self.assertRaisesRegex(m.MaintenanceError, "changed_during_cleanup"):
                m.clean_baseline(self.home, m.BASELINES[0])
        self.assertEqual(p.read_bytes(), b"user edited during cleanup")
        self.assertEqual(list(p.parent.glob(".aegis-uninstall-*")), [])

    def test_metadata_failure_preserves_original(self):
        p = self.baseline()
        with patch.object(m, "copy_metadata", side_effect=m.MaintenanceError("metadata_failed")):
            with self.assertRaises(m.MaintenanceError):
                m.clean_baseline(self.home, m.BASELINES[0])
        self.assertEqual(p.read_bytes(), self.data)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin metadata")
    def test_mac_extended_attributes_survive(self):
        p = self.baseline()
        subprocess.run(["/usr/bin/xattr", "-w", "org.aegis.fixture", "fixture metadata", str(p)], check=True, capture_output=True)
        self.assertTrue(m.clean_baseline(self.home, m.BASELINES[0]))
        self.assertEqual(subprocess.check_output(["/usr/bin/xattr", "-p", "org.aegis.fixture", str(p)]).strip(), b"fixture metadata")

    def test_service_failure_prevents_all_file_changes(self):
        p = self.baseline()
        services = m.LaunchServices(lambda args: 0 if args[0] == "print" else 5)
        with self.assertRaisesRegex(m.MaintenanceError, "service_stop_failed"):
            self.uninstall(services)
        self.assertEqual(p.read_bytes(), self.data)
        self.assertTrue(self.app.exists())
        self.assertFalse((self.root / "AegisUninstallArchive").exists())

    def test_unknown_service_state_is_not_treated_as_absent(self):
        for status in (1, 5, 112, 125):
            with self.subTest(status=status):
                services = m.LaunchServices(lambda args: 0 if args == ["print", "system"] else status)
                with self.assertRaises(m.MaintenanceError):
                    services.stop("system", "com.aegis.agent")

    def test_stop_requires_confirmed_disappearance(self):
        with patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(m.MaintenanceError, "still_registered"):
                m.LaunchServices(lambda args: 0).stop("system", "com.aegis.agent")
        results = iter([0, 0, 0, 5])
        with self.assertRaisesRegex(m.MaintenanceError, "unconfirmed"):
            m.LaunchServices(lambda args: next(results)).stop("system", "com.aegis.agent")

    def test_missing_user_domain_and_absent_service_are_idempotent(self):
        m.LaunchServices(lambda args: 112).stop("gui/501", "com.aegis.agent")
        m.LaunchServices(lambda args: 0 if args[1] == "system" else 113).stop("system", "com.aegis.agent")
        with self.assertRaises(m.MaintenanceError):
            m.LaunchServices(lambda args: 112).stop("system", "com.aegis.agent")

    def test_uninstall_stops_all_labels_and_retains_state(self):
        self.baseline()
        (self.app / "synthetic-state.json").write_text('{"fixture":true}')
        quarantine = self.home / ".aegis-quarantine"
        quarantine.mkdir()
        (quarantine / "isolated-fixture").write_bytes(b"retained")
        repository = self.home / "repo"
        repository.mkdir()
        (repository / "AGENTS.md").write_bytes(self.data)
        for label in m.SYSTEM_LABELS:
            (self.daemons / (label + ".plist")).write_bytes(b"synthetic plist")
        class Recorder:
            calls = []
            def stop(self, domain, label):
                self.calls.append((domain, label))
        recorder = Recorder()
        result = self.uninstall(recorder)
        self.assertEqual(result["status"], "uninstalled_with_retained_state")
        self.assertEqual(result["archived_items"], 4)
        self.assertEqual(result["cleaned_baselines"], 1)
        self.assertEqual(len(recorder.calls), 7)
        self.assertFalse(self.app.exists())
        self.assertEqual((quarantine / "isolated-fixture").read_bytes(), b"retained")
        self.assertEqual((repository / "AGENTS.md").read_bytes(), self.data)
        archives = list((self.root / "AegisUninstallArchive").iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0].stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((archives[0] / "status.json").read_text()), result)
        self.assertTrue((archives[0] / "system-runtime/synthetic-state.json").exists())
        self.assertEqual(self.uninstall()["archived_items"], 0)

    def test_malformed_baseline_retains_runtime_and_plists(self):
        self.baseline(data=m.START)
        plist = self.daemons / "com.aegis.agent.plist"
        plist.write_bytes(b"fixture")
        with self.assertRaises(m.MaintenanceError):
            self.uninstall()
        self.assertTrue(self.app.exists())
        self.assertTrue(plist.exists())

    def test_archive_source_symlink_is_not_followed(self):
        outside = self.root / "outside"
        outside.write_bytes(b"unchanged")
        (self.daemons / "com.aegis.agent.plist").symlink_to(outside)
        with self.assertRaises(m.MaintenanceError):
            self.uninstall()
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertTrue(self.app.exists())
        journal = next((self.root / "AegisUninstallArchive").glob("*/status.json"))
        self.assertEqual(json.loads(journal.read_text())["status"], "partial")


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("AEGIS_RUN_LAUNCHD_TESTS") == "1", "opt-in isolated launchd job")
class LiveLaunchdTests(unittest.TestCase):
    def test_real_keepalive_job_stops_and_stays_unregistered(self):
        label = "com.aegis.lab." + secrets.token_hex(8)
        domain = "system" if os.geteuid() == 0 else "gui/" + str(os.geteuid())
        with tempfile.TemporaryDirectory(prefix="aegis-launchd-lab-") as temporary:
            path = Path(temporary).resolve() / (label + ".plist")
            path.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": ["/bin/sleep", "600"], "KeepAlive": True, "RunAtLoad": True}))
            try:
                subprocess.run(["/bin/launchctl", "bootstrap", domain, str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                pid = None
                for _ in range(50):
                    # This is our synthetic /bin/sleep service, never a user job.
                    output = subprocess.check_output(["/bin/launchctl", "print", domain + "/" + label], text=True)
                    match = re.search(r"(?m)^\s*pid = ([0-9]+)\s*$", output)
                    if match and int(match.group(1)) > 1:
                        candidate = int(match.group(1))
                        # launchd first exposes a root xpcproxy PID. Wait until
                        # it has exec'd our fixture before probing process exit.
                        process = subprocess.run(["/bin/ps", "-p", str(candidate), "-o", "comm="], capture_output=True, text=True)
                        if process.returncode == 0 and process.stdout.strip() == "/bin/sleep":
                            pid = candidate
                            break
                    time.sleep(0.1)
                self.assertIsNotNone(pid, "fixture process did not start")
                os.kill(pid, 0)
                self.assertEqual(m.LaunchServices._run(["print", domain + "/" + label]), 0)
                m.LaunchServices().stop(domain, label)
                self.assertEqual(m.LaunchServices._run(["print", domain + "/" + label]), 113)
                for _ in range(50):
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("fixture process survived bootout")
                m.LaunchServices().stop(domain, label)
            finally:
                subprocess.run(["/bin/launchctl", "bootout", domain + "/" + label], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    unittest.main()
