"""Read-only health checks using synthetic state, never host installation data."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

DL = Path(__file__).resolve().parents[1] / "public/downloads"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DL / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


maintenance = load("diagnostics_maintenance", "aegis_macos_maintenance.py")
with patch.dict(sys.modules, {"aegis_macos_maintenance": maintenance}):
    configuration = load("diagnostic_configuration", "aegis_macos_configuration.py")
    with patch.dict(sys.modules, {"aegis_macos_configuration": configuration}):
        diagnostics = load("diagnostics", "aegis_macos_diagnostics.py")
agent = load("diagnostics_agent", "aegis_agent.py")


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-health-fixture-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.version = agent.AGENT_VERSION
        self.artifact = "aegis-agent-darwin-" + ("arm64" if os.uname().machine == "arm64" else "x64")
        self.now = 2000000000
        self.prepare()

    def write(self, name, value, mode=0o600):
        path = self.root / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(mode)

    def prepare(self, binary=b"synthetic-native-binary"):
        self.write("aegis-agent", binary, 0o755)
        self.write("aegis-security-baseline.md", b"synthetic baseline", 0o644)
        self.manifest = {"schema": "aegis.macos-runtime/v1", "agent_version": self.version, "files": {
            self.artifact: hashlib.sha256(binary).hexdigest(),
            "aegis-security-baseline.md": hashlib.sha256(b"synthetic baseline").hexdigest()}}
        self.write("aegis-runtime-manifest.json", self.manifest, 0o644)
        self.write("aegis-policy.json", {"schema": "aegis.policy/v1", "version": "6.1.2"})
        self.write("reporting.json", {"schema": "aegis.reporting/v1", "report_url": "https://aegis.example.test/aegis/v1/reports",
                                      "report_token": "synthetic-token-" * 4, "signing_secret": "synthetic-secret-" * 4})
        self.upload = {"schema": "aegis.upload-status/v1", "status": "accepted", "collector_host": "aegis.example.test", "last_success": self.now}
        self.upload["configuration_fingerprint"] = configuration.config_fingerprint(json.loads((self.root / "reporting.json").read_text()))
        self.write("upload-status.json", self.upload)
        self.report = {"schema": "aegis.report/v1", "agent_version": self.version, "policy_version": "6.1.2",
                       "scanned_at": self.now, "device_id": "012345abcdef", "hostname": "SYNTHETIC-PRIVATE-HOST",
                       "serial": "SYNTHETIC-PRIVATE-SERIAL", "os_user": "SYNTHETIC-PRIVATE-USER",
                       "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                       "findings": [{"severity": "high", "kind": "fixture", "path": "/synthetic/private-path", "message": "SYNTHETIC-PRIVATE-CONTENT"}]}
        self.write("last-report.json", self.report)

    def collect(self, **kwargs):
        return diagnostics.collect(self.root, self.version, agent.validate_policy, owner=os.geteuid(), now=self.now,
                                   probe=kwargs.pop("probe", lambda _: (True, True)),
                                   legacy_probe=kwargs.pop("legacy_probe", lambda: False), **kwargs)

    def test_healthy_summary_is_read_only_and_contains_no_identity_or_content(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        value = self.collect()
        for key in ("AegisInstalled", "AegisIntegrityValid", "AegisLaunchDaemonHealthy", "AegisReportingConfigured",
                    "AegisReportingHealthy", "AegisReportValid", "AegisScanRecent", "AegisFindingsKnown"):
            self.assertIs(value[key], True, key)
        self.assertEqual(value["AegisHighFindings"], 1)
        self.assertEqual(value["AegisDiagnosticIssues"], [])
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})
        for forbidden in ("SYNTHETIC", "synthetic", "012345abcdef", "example.test", "signing_secret", str(self.root)):
            self.assertNotIn(forbidden, json.dumps(value))

    def test_tampering_and_malformed_manifest_fail_integrity(self):
        for filename, value in (("aegis-agent", b"different"), ("aegis-security-baseline.md", b"different"),
                                ("aegis-runtime-manifest.json", {"files": []}), ("aegis-runtime-manifest.json", [])):
            with self.subTest(filename=filename, value=value):
                self.prepare()
                self.write(filename, value)
                self.assertFalse(self.collect()["AegisIntegrityValid"])

    def test_active_policy_is_not_pinned_to_factory_hash(self):
        self.write("aegis-policy.json", {"schema": "aegis.policy/v1", "version": "6.2.0"})
        self.report["policy_version"] = "6.2.0"
        self.write("last-report.json", self.report)
        value = self.collect()
        self.assertTrue(value["AegisIntegrityValid"])
        self.assertTrue(value["AegisReportValid"])
        self.assertEqual(value["AegisPolicyVersion"], "6.2.0")

    def test_invalid_report_never_appears_as_known_zero_risk(self):
        for change in ({"summary": dict.fromkeys(diagnostics.SEVERITIES, 0)}, {"summary": dict.fromkeys(diagnostics.SEVERITIES, False)},
                       {"device_id": "invalid"}, {"agent_version": "0.0.0"}, {"policy_version": "0.0.0"},
                       {"findings": [None]}, {"scanned_at": True}):
            with self.subTest(change=change):
                self.write("last-report.json", {**self.report, **change})
                value = self.collect()
                self.assertFalse(value["AegisReportValid"])
                self.assertFalse(value["AegisFindingsKnown"])

    def test_stale_future_and_boolean_timestamps_are_not_recent(self):
        for timestamp in (self.now - 7200, self.now + 1, True, "recent"):
            with self.subTest(timestamp=timestamp):
                self.write("last-report.json", {**self.report, "scanned_at": timestamp})
                self.write("upload-status.json", {**self.upload, "last_success": timestamp})
                value = self.collect()
                self.assertFalse(value["AegisScanRecent"])
                self.assertFalse(value["AegisReportingHealthy"])

    def test_upload_requires_same_collector_and_valid_private_config(self):
        self.write("upload-status.json", {**self.upload, "collector_host": "other.example.test"})
        self.assertFalse(self.collect()["AegisReportingHealthy"])
        self.write("upload-status.json", self.upload)
        (self.root / "reporting.json").chmod(0o644)
        value = self.collect()
        self.assertFalse(value["AegisReportingConfigured"])
        self.assertFalse(value["AegisReportingHealthy"])

    def test_old_receipt_cannot_validate_rotated_credentials_or_changed_url_path(self):
        current = json.loads((self.root / "reporting.json").read_text())
        for change in ({"report_token": "replacement-token-" * 4}, {"signing_secret": "replacement-secret-" * 4},
                       {"report_url": "https://aegis.example.test/another/reports"}):
            replacement = {**current, **change}
            self.write("reporting.json", replacement)
            self.write("upload-status.json", self.upload)
            self.assertFalse(self.collect()["AegisReportingHealthy"])
            self.write("upload-status.json", {**self.upload, "configuration_fingerprint": configuration.config_fingerprint(replacement)})
            self.assertTrue(self.collect()["AegisReportingHealthy"])
        legacy = {key: value for key, value in self.upload.items() if key != "configuration_fingerprint"}
        self.write("upload-status.json", legacy)
        self.assertFalse(self.collect()["AegisReportingHealthy"])

    def test_invalid_reporting_urls_and_shared_credentials_are_rejected(self):
        config = json.loads((self.root / "reporting.json").read_text())
        for url in ("http://aegis.example.test/reports", "https://aegis.example.test:invalid/reports",
                    "https://aegis.example.test:0/reports", "https://aegis.example.test:99999/reports",
                    "https://user@aegis.example.test/reports", "https://aegis.example.test/reports?token=fixture",
                    "https://aegis.example.test/reports\n"):
            self.write("reporting.json", {**config, "report_url": url})
            self.assertFalse(self.collect()["AegisReportingConfigured"])
        self.write("reporting.json", {**config, "signing_secret": config["report_token"]})
        self.assertFalse(self.collect()["AegisReportingConfigured"])

    def test_unsafe_files_refused_without_blocking_or_following_links(self):
        path = self.root / "last-report.json"
        other = self.root / "synthetic-original"
        path.rename(other)
        for kind in ("symlink", "hardlink", "fifo", "writable", "oversize", "owner"):
            with self.subTest(kind=kind):
                if kind == "symlink": path.symlink_to(other)
                elif kind == "hardlink": os.link(other, path)
                elif kind == "fifo": os.mkfifo(path)
                else:
                    path.write_bytes(b"fixture")
                    path.chmod(0o666 if kind == "writable" else 0o600)
                limit = 1 if kind == "oversize" else 10000
                owner = os.geteuid() + 1 if kind == "owner" else os.geteuid()
                with self.assertRaises((OSError, diagnostics.DiagnosticError)):
                    diagnostics.read_file(self.root, path.name, limit, owner)
                path.unlink()

    def test_missing_state_and_symlinked_ancestor_are_unhealthy(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            empty = Path(temp)
            alias = self.root / "alias"
            alias.symlink_to(empty, target_is_directory=True)
            for root in (empty, alias):
                value = diagnostics.collect(root, self.version, agent.validate_policy, owner=os.geteuid(),
                                            probe=lambda _: (False, False), legacy_probe=lambda: False)
                self.assertFalse(value["AegisIntegrityValid"])
                self.assertFalse(value["AegisReportValid"])
                self.assertFalse(value["AegisLaunchDaemonHealthy"])

    def test_registered_service_is_not_necessarily_healthy(self):
        self.assertFalse(self.collect(probe=lambda _: (True, False))["AegisLaunchDaemonHealthy"])
        value = self.collect(legacy_probe=lambda: True)
        self.assertTrue(value["AegisLegacyServicePresent"])
        self.assertFalse(value["AegisLaunchDaemonHealthy"])
        def unavailable():
            raise diagnostics.DiagnosticError("fixture")
        self.assertFalse(self.collect(legacy_probe=unavailable)["AegisLaunchDaemonHealthy"])
        (self.root / "watch-cleanup-pending.json").symlink_to("missing")
        value = self.collect()
        self.assertFalse(value["AegisLaunchDaemonHealthy"])
        self.assertIn("watch_cleanup_requires_verification", value["AegisDiagnosticIssues"])

    def test_update_receipt_required_for_version_drift_and_bound_to_artifact(self):
        self.manifest["agent_version"] = "0.0.0"
        self.write("aegis-runtime-manifest.json", self.manifest)
        self.assertFalse(self.collect()["AegisIntegrityValid"])
        receipt = {"schema": "aegis.update-receipt/v1", "artifact": self.artifact,
                   "agent_version": self.version, "sha256": self.manifest["files"][self.artifact]}
        self.write("aegis-update-receipt.json", receipt)
        self.assertTrue(self.collect()["AegisIntegrityValid"])
        for change in ({"artifact": "other"}, {"agent_version": "0.0.0"}, {"sha256": "0" * 64}):
            self.write("aegis-update-receipt.json", {**receipt, **change})
            self.assertFalse(self.collect()["AegisIntegrityValid"])
        self.write("aegis-update-receipt.json", receipt, 0o644)
        self.assertFalse(self.collect()["AegisIntegrityValid"])

    @unittest.skipUnless(sys.platform == "darwin" and os.geteuid() == 0 and os.environ.get("AEGIS_FROZEN_AGENT"),
                         "explicit native artifact and isolated root fixture required")
    def test_frozen_diagnostics_read_only_root_fixture_without_network_or_external_python(self):
        binary = Path(os.environ["AEGIS_FROZEN_AGENT"]).read_bytes()
        self.prepare(binary)
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        result = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)(deny process-exec (regex #\"/python[0-9.]*$\"))",
                                 str(self.root / "aegis-agent"), "--diagnostics"],
                                env={**os.environ, "PATH": "/nonexistent", "PYTHONHOME": "/nonexistent", "PYTHONPATH": "/nonexistent"},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["AegisIntegrityValid"])
        self.assertTrue(value["AegisReportingConfigured"])
        self.assertTrue(value["AegisReportValid"])
        self.assertFalse(value["AegisLaunchDaemonHealthy"])
        self.assertNotIn("SYNTHETIC", result.stdout)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})


class ProbeAndDispatchTests(unittest.TestCase):
    def test_service_probe_checks_program_state_and_live_pid(self):
        root = Path("/synthetic")
        stdout = "\tstate = running\n\tpid = 12345\n\tprogram = /synthetic/aegis-agent\n"
        with patch.object(diagnostics.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=stdout)), patch.object(diagnostics.os, "kill") as kill:
            self.assertEqual(diagnostics.service_status(root), (True, True))
            kill.assert_called_once_with(12345, 0)
            kill.side_effect = ProcessLookupError()
            self.assertEqual(diagnostics.service_status(root), (True, False))
        for text in (stdout.replace("running", "exited"), stdout.replace("/synthetic/", "/other/"), stdout.replace("12345", "0")):
            with patch.object(diagnostics.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=text)):
                self.assertEqual(diagnostics.service_status(root), (True, False))
        with patch.object(diagnostics.subprocess, "run", return_value=types.SimpleNamespace(returncode=113, stdout="")):
            self.assertEqual(diagnostics.service_status(root), (False, False))
        with patch.object(diagnostics.subprocess, "run", return_value=types.SimpleNamespace(returncode=1, stdout="")):
            with self.assertRaises(diagnostics.DiagnosticError): diagnostics.service_status(root)

    def test_diagnostics_exclusive_dispatch_and_nonroot_refusal(self):
        with patch.dict(sys.modules, {"aegis_macos_diagnostics": diagnostics}), patch.object(sys, "platform", "darwin"), patch.object(diagnostics, "main", return_value=17) as entry:
            with patch.object(sys, "argv", ["agent", "--diagnostics"]):
                self.assertEqual(agent.main(), 17)
            entry.reset_mock()
            for argv in (["--diagnostics", "--watch"], ["--diagnostics=true"], ["--", "--diagnostics"], ["--diagnostics", "--uninstall-system"]):
                with patch.object(sys, "argv", ["agent", *argv]): self.assertEqual(agent.main(), 2)
            entry.assert_not_called()
        with patch.object(os, "geteuid", return_value=501), patch.object(diagnostics, "collect") as collect, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostics.main(Path("/unused"), "1.0.0", agent.validate_policy), 2)
            self.assertFalse(json.loads(output.getvalue())["AegisInstalled"])
            collect.assert_not_called()

    def test_update_receipt_records_applied_digest_and_reports_write_failure(self):
        result = {"updated": True, "from": "1.0.0", "to": "1.1.0", "sha256": "a" * 64}
        updater = types.SimpleNamespace(check_and_apply=lambda *a, **kw: result)
        with patch.dict(sys.modules, {"aegis_self_update": updater}), patch.object(sys, "platform", "darwin"), patch.object(sys, "frozen", True, create=True), patch.object(agent, "hardware_device_id", return_value="fixture"), patch.object(agent, "write_private_atomic") as write:
            policy = {"agent_self_update": {"enabled": True}}
            agent.maybe_self_update(policy, "https://aegis.example.test/aegis/v1/reports")
            self.assertEqual(json.loads(write.call_args.args[1])["sha256"], result["sha256"])
            self.assertEqual(agent._SELF_UPDATE_RESULT["reason"], "ok")
            write.side_effect = OSError("synthetic failure")
            agent.maybe_self_update(policy, "https://aegis.example.test/aegis/v1/reports")
            self.assertTrue(agent._SELF_UPDATE_RESULT["updated"])
            self.assertEqual(agent._SELF_UPDATE_RESULT["reason"], "updated_receipt_unavailable")


@unittest.skipUnless(sys.platform == "darwin", "Mac wrapper permission checks")
class ComplianceWrapperTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-compliance-wrapper-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        library = self.root / "Library"
        self.app = library / "Application Support/AegisAgent"
        self.app.mkdir(parents=True)
        for directory in (library, self.app.parent, self.app): directory.chmod(0o755)
        self.calls = self.root / "calls"
        stat = self.root / "stat-fixture"
        stat.write_text('#!/bin/sh\nif [ "$2" = "%u" ]; then echo "${AEGIS_TEST_OWNER:-0}"; else exec /usr/bin/stat "$@"; fi\n')
        stat.chmod(0o755)
        self.source = (DL / "mdm-macos-compliance.sh").read_text().replace("/Library", str(library))
        self.source = self.source.replace("/usr/bin/id -u", "printf 0").replace("/usr/bin/stat", '"' + str(stat) + '"')
        self.wrapper = self.root / "compliance.sh"
        self.wrapper.write_text(self.source)
        self.env = {**os.environ, "AEGIS_TEST_CALLS": str(self.calls), "PATH": "/nonexistent"}
        self.binary = self.app / "aegis-agent"
        self.binary.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$AEGIS_TEST_CALLS"\ncase "$1" in\n--diagnostics-selftest) exit "${AEGIS_TEST_SELFTEST_RC:-0}";;\n--diagnostics) printf \'%s\\n\' \'{"fixture":true}\'; exit 0;;\n*) exit 2;;\nesac\n')
        self.binary.chmod(0o755)

    def run_wrapper(self, *args):
        return subprocess.run(["/bin/sh", str(self.wrapper), *args], env=self.env, capture_output=True, text=True, timeout=15)

    def test_checks_capability_then_delegates_without_external_python(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"fixture": True})
        self.assertEqual(self.calls.read_text().splitlines(), ["--diagnostics-selftest", "--diagnostics"])

    def test_missing_untrusted_and_writable_runtime_refused_before_execution(self):
        for kind in ("missing", "owner", "directory_mode", "file_mode", "symlink"):
            with self.subTest(kind=kind):
                backup = self.root / "backup"
                if kind in ("missing", "symlink"):
                    self.binary.rename(backup)
                    if kind == "symlink": self.binary.symlink_to(backup)
                if kind == "owner": self.env["AEGIS_TEST_OWNER"] = "501"
                if kind == "directory_mode": self.app.chmod(0o777)
                if kind == "file_mode": self.binary.chmod(0o777)
                result = self.run_wrapper()
                self.assertEqual(result.returncode, 1)
                self.assertFalse(json.loads(result.stdout)["AegisInstalled"])
                self.assertFalse(self.calls.exists())
                if kind == "symlink": self.binary.unlink()
                if kind in ("missing", "symlink"): backup.rename(self.binary)
                self.env.pop("AEGIS_TEST_OWNER", None)
                self.app.chmod(0o755)
                self.binary.chmod(0o755)

    def test_nonroot_extra_arguments_and_failed_capability_return_structured_failure(self):
        self.wrapper.write_text(self.source.replace("printf 0", "printf 501"))
        self.assertEqual(self.run_wrapper().returncode, 2)
        self.wrapper.write_text(self.source)
        self.assertEqual(self.run_wrapper("--unexpected").returncode, 2)
        self.assertFalse(self.calls.exists())
        self.env["AEGIS_TEST_SELFTEST_RC"] = "7"
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["AegisLaunchDaemonHealthy"])
        self.assertEqual(self.calls.read_text().splitlines(), ["--diagnostics-selftest"])


if __name__ == "__main__":
    unittest.main()
