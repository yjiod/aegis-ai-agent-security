"""MDM bootstrap boundaries; Installer is always a fixture, never a host install."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "public/downloads/mdm-macos-install.sh"
TEAM = "TESTTEAM01"


@unittest.skipUnless(sys.platform == "darwin", "macOS system tools and sandbox")
class MacMdmInstallTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-mdm-fixture-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.stages = self.root / "stages"
        self.stages.mkdir()
        self.package = self.root / "synthetic.pkg"
        self.package.write_bytes(b"synthetic-package")
        self.package.chmod(0o600)
        self.calls = self.root / "calls"
        self.assessment = self.root / "assessment.plist"
        self.write_assessment()
        self.existing = self.root / "existing-installation"
        self.existing.mkdir()
        for name in ("aegis-agent", "reporting.json", "aegis-policy.json", "service-state"):
            (self.existing / name).write_bytes(b"synthetic-existing-state")
        self.before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.existing.iterdir()}
        mock = '''#!/bin/sh
command=${0##*/}
printf '%s\\0' "$command" "$@" >> "$AEGIS_TEST_CALLS"
printf '\\0' >> "$AEGIS_TEST_CALLS"
case "$command" in
id) printf '%s\\n' "${AEGIS_TEST_UID:-0}";;
launchctl) exit "${AEGIS_TEST_LEGACY_RC:-113}";;
stat)
  if [ "$2" = '%u' ]; then printf '%s\\n' "${AEGIS_TEST_OWNER:-0}"; else exec /usr/bin/stat "$@"; fi;;
curl)
  [ "${AEGIS_TEST_DOWNLOAD_RC:-0}" = 0 ] || { echo 'synthetic-private-download-error' >&2; exit "$AEGIS_TEST_DOWNLOAD_RC"; }
  while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; output=$1; fi; shift; done
  /bin/cp -P -X "$AEGIS_TEST_PACKAGE" "$output";;
pkgutil)
  [ "${AEGIS_TEST_SIGNATURE_RC:-0}" = 0 ] || exit "$AEGIS_TEST_SIGNATURE_RC"
  printf 'Package: synthetic\\nStatus: fixture only\\nCertificate Chain:\\n  1. Developer ID Installer: Fixture Publisher (%s)\\n' "${AEGIS_TEST_TEAM:-TESTTEAM01}";;
spctl)
  if [ "$1" = --status ]; then
    printf 'assessments %s\\n' "${AEGIS_TEST_ASSESSMENT_STATE:-enabled}"
    [ "${AEGIS_TEST_ASSESSMENT_STATE:-enabled}" = enabled ]; exit $?
  fi
  [ "${AEGIS_TEST_ASSESSMENT_RC:-0}" = 0 ] || exit "$AEGIS_TEST_ASSESSMENT_RC"
  if [ "${AEGIS_TEST_TAMPER:-0}" = 1 ]; then for package do :; done; printf changed >> "$package"; fi
  /bin/cat "$AEGIS_TEST_ASSESSMENT";;
installer)
  printf 'synthetic-private-installer-output\\n'
  exit "${AEGIS_TEST_INSTALLER_RC:-0}";;
*) exit 99;;
esac
'''
        source = SCRIPT.read_text()
        for tool, location in (("id", "/usr/bin/id"), ("stat", "/usr/bin/stat"), ("curl", "/usr/bin/curl"),
                               ("pkgutil", "/usr/sbin/pkgutil"), ("spctl", "/usr/sbin/spctl"), ("installer", "/usr/sbin/installer"),
                               ("launchctl", "/bin/launchctl")):
            path = self.bin / tool
            path.write_text(mock)
            path.chmod(0o755)
            source = source.replace(location, '"' + str(path) + '"')
        source = source.replace("/private/var/tmp/aegis-mdm.XXXXXXXX", str(self.stages / "aegis-mdm.XXXXXXXX"))
        source = source.replace("/Library/Application Support/AegisAgent", str(self.root / "Library/Application Support/AegisAgent"))
        source = source.replace("/Library/LaunchDaemons", str(self.root / "Library/LaunchDaemons"))
        source = source.replace("/Users/", str(self.root / "Users") + "/")
        self.wrapper = self.root / "mdm.sh"
        self.wrapper.write_text(source)
        self.env = {**os.environ, "AEGIS_MACOS_PKG_SHA256": hashlib.sha256(self.package.read_bytes()).hexdigest(),
                    "AEGIS_MACOS_TEAM_ID": TEAM, "AEGIS_MACOS_PKG_URL": "https://aegis.example.test/downloads/agent.pkg",
                    "AEGIS_MACOS_PKG_PATH": "", "AEGIS_TEST_PACKAGE": str(self.package),
                    "AEGIS_TEST_CALLS": str(self.calls), "AEGIS_TEST_ASSESSMENT": str(self.assessment),
                    "PATH": "/nonexistent", "PYTHONHOME": "/nonexistent", "PYTHONPATH": "/nonexistent"}

    def write_assessment(self, verdict=True, source="Notarized Developer ID", **extra):
        self.assessment.write_bytes(plistlib.dumps({"assessment:verdict": verdict,
            "assessment:authority": {"assessment:authority:source": source, **extra}}))

    def run_script(self, *args):
        profile = '''(version 1)(allow default)(deny network*)
(deny process-exec (regex #"/python[0-9.]*$") (literal "/usr/sbin/installer") (literal "/bin/launchctl"))
(deny file-write* (require-all (require-not (subpath (param "FIXTURE"))) (require-not (literal "/dev/null"))))'''
        result = subprocess.run(["/usr/bin/sandbox-exec", "-D", "FIXTURE=" + str(self.root), "-p", profile, "/bin/sh", str(self.wrapper), *args],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertNotIn("synthetic-private", result.stdout + result.stderr)
        self.assertEqual(self.before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.existing.iterdir()})
        self.assertEqual(list(self.stages.iterdir()), [])
        return result, json.loads(result.stdout)

    def records(self):
        if not self.calls.exists(): return []
        return [[x.decode() for x in item.split(b"\0")] for item in self.calls.read_bytes().split(b"\0\0") if item]

    def assert_no_install(self):
        self.assertNotIn("installer", [x[0] for x in self.records()])

    def test_positive_fixture_orders_gates_before_installer_and_leaves_health_pending(self):
        result, value = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value["status"], "installed_health_pending")
        self.assertTrue(value["installer_succeeded"])
        self.assertFalse(value["health_verified"])
        commands = [x[0] for x in self.records()]
        self.assertLess(commands.index("curl"), commands.index("pkgutil"))
        self.assertLess(commands.index("pkgutil"), commands.index("spctl"))
        self.assertLess(commands.index("spctl"), commands.index("installer"))
        download = next(x for x in self.records() if x[0] == "curl")
        self.assertIn("=https", download)
        self.assertIn("--max-filesize", download)
        self.assertNotIn("--location", download)
        self.assertNotIn("--insecure", download)
        install = next(x for x in self.records() if x[0] == "installer")
        self.assertEqual(install[1], "-pkg")
        self.assertEqual(install[-2:], ["-target", "/"])

    def test_local_cache_does_not_download_or_modify_source(self):
        self.env.update(AEGIS_MACOS_PKG_URL="", AEGIS_MACOS_PKG_PATH=str(self.package))
        before = self.package.read_bytes()
        result, _ = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("curl", [x[0] for x in self.records()])
        self.assertEqual(self.package.read_bytes(), before)

    def test_platform_missing_key_stdout_cannot_pollute_public_result(self):
        probe = self.bin / "plutil"
        probe.write_text('''#!/bin/sh
/usr/bin/plutil "$@"
code=$?
[ "$code" = 0 ] || printf 'synthetic-private-missing-key-error\\n'
exit "$code"
''')
        probe.chmod(0o755)
        self.wrapper.write_text(self.wrapper.read_text().replace("/usr/bin/plutil", '"' + str(probe) + '"'))
        result, value = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value["status"], "installed_health_pending")

    def test_missing_digest_publisher_and_privilege_refused_before_staging(self):
        for field, replacement in (("AEGIS_MACOS_PKG_SHA256", ""), ("AEGIS_MACOS_PKG_SHA256", 'invalid"input'),
                                   ("AEGIS_MACOS_TEAM_ID", ""), ("AEGIS_MACOS_TEAM_ID", "bad.*"), ("AEGIS_TEST_UID", "501")):
            old = self.env.get(field)
            self.env[field] = replacement
            result, value = self.run_script()
            self.assertEqual(result.returncode, 2)
            self.assertFalse(value["installation_attempted"])
            self.assertNotIn("curl", [x[0] for x in self.records()])
            if old is None: self.env.pop(field)
            else: self.env[field] = old
        self.assertEqual(self.run_script("--extra")[0].returncode, 2)
        self.assert_no_install()

    def test_invalid_urls_never_reach_download(self):
        for url in ("http://aegis.example.test/p.pkg", "https://user@aegis.example.test/p.pkg",
                    "https://aegis.example.test/p.pkg?token=fixture", "https://aegis.example.test/p.pkg\n",
                    "https://aegis.example.test/$(id).pkg", "https://aegis.example.test/p.pkg#fragment"):
            self.env["AEGIS_MACOS_PKG_URL"] = url
            result, value = self.run_script()
            self.assertEqual(value["status"], "invalid_package_url")
            self.assertEqual(result.returncode, 2)
        self.assertNotIn("curl", [x[0] for x in self.records()])

    def test_local_source_conflict_links_permissions_owner_and_oversize_refused(self):
        self.env["AEGIS_MACOS_PKG_PATH"] = str(self.package)
        self.assertEqual(self.run_script()[1]["status"], "ambiguous_package_source")
        self.env["AEGIS_MACOS_PKG_URL"] = ""
        self.env["AEGIS_TEST_OWNER"] = "501"
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        self.env.pop("AEGIS_TEST_OWNER")
        self.package.chmod(0o666)
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        self.package.chmod(0o600)
        alias = self.root / "alias.pkg"
        alias.symlink_to(self.package)
        self.env["AEGIS_MACOS_PKG_PATH"] = str(alias)
        self.assertEqual(self.run_script()[1]["status"], "invalid_local_package")
        alias.unlink(); os.link(self.package, alias)
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        alias.unlink()
        with self.package.open("r+b") as f: f.truncate(134217729)
        self.env["AEGIS_MACOS_PKG_PATH"] = str(self.package)
        self.assertEqual(self.run_script()[1]["status"], "package_size_refused")
        self.assert_no_install()

    def test_download_digest_signature_publisher_and_assessment_failures_preserve_existing(self):
        cases = (("AEGIS_TEST_DOWNLOAD_RC", "28", "package_download_failed"),
                 ("AEGIS_MACOS_PKG_SHA256", "0" * 64, "package_digest_mismatch"),
                 ("AEGIS_TEST_SIGNATURE_RC", "1", "package_signature_rejected"),
                 ("AEGIS_TEST_TEAM", "OTHERTEAM1", "package_publisher_mismatch"),
                 ("AEGIS_TEST_ASSESSMENT_STATE", "disabled", "platform_assessment_disabled"),
                 ("AEGIS_TEST_ASSESSMENT_RC", "3", "package_assessment_rejected"),
                 ("AEGIS_TEST_TAMPER", "1", "package_changed_after_assessment"))
        for field, replacement, status in cases:
            old = self.env.get(field)
            self.env[field] = replacement
            result, value = self.run_script()
            self.assertEqual(result.returncode, 1)
            self.assertEqual(value["status"], status)
            self.assertFalse(value["installation_attempted"])
            if old is None: self.env.pop(field)
            else: self.env[field] = old
        self.assert_no_install()

    def test_raw_assessment_cannot_use_override_false_verdict_or_unnotarized_source(self):
        for kwargs, status in (({"verdict": False}, "package_assessment_rejected"),
                               ({"verdict": "true"}, "invalid_package_assessment"),
                               ({"source": "Unnotarized Developer ID"}, "package_notarization_unconfirmed"),
                               ({"assessment:authority:override": "security disabled"}, "package_assessment_override_refused"),
                               ({"assessment:authority:override": ""}, "package_assessment_override_refused"),
                               ({"assessment:authority:verdict": False}, "package_assessment_rejected")):
            self.write_assessment(**kwargs)
            result, value = self.run_script()
            self.assertEqual(result.returncode, 1)
            self.assertEqual(value["status"], status)
        self.assessment.write_text("not a plist")
        self.assertEqual(self.run_script()[1]["status"], "invalid_package_assessment")
        self.assert_no_install()

    def test_installer_failure_is_not_claimed_to_have_rolled_back(self):
        self.env["AEGIS_TEST_INSTALLER_RC"] = "7"
        result, value = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value["status"], "installer_failed_state_requires_verification")
        self.assertTrue(value["installation_attempted"])
        self.assertFalse(value["installer_succeeded"])

    def test_legacy_service_or_pending_cleanup_require_migration_before_download(self):
        for code, status in (("0", "legacy_service_migration_required"), ("1", "legacy_service_state_unavailable")):
            self.env["AEGIS_TEST_LEGACY_RC"] = code
            self.assertEqual(self.run_script()[1]["status"], status)
        self.env.pop("AEGIS_TEST_LEGACY_RC")
        pending = self.root / "Library/Application Support/AegisAgent/watch-cleanup-pending.json"
        pending.parent.mkdir(parents=True)
        pending.symlink_to("missing")
        self.assertEqual(self.run_script()[1]["status"], "prior_cleanup_requires_verification")
        pending.unlink()
        legacy = self.root / "Library/LaunchDaemons/com.company.aegis-agent.plist"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("synthetic legacy state")
        self.assertEqual(self.run_script()[1]["status"], "legacy_service_migration_required")
        self.assertEqual(legacy.read_text(), "synthetic legacy state")
        legacy.unlink()
        user_legacy = self.root / "Users/fixture/Library/LaunchAgents/com.aegis.agent.plist"
        user_legacy.parent.mkdir(parents=True)
        user_legacy.write_text("synthetic user legacy state")
        self.assertEqual(self.run_script()[1]["status"], "legacy_service_migration_required")
        self.assertTrue(user_legacy.exists())
        self.assertNotIn("curl", [x[0] for x in self.records()])
        self.assert_no_install()

    def test_real_unsigned_package_rejected_by_system_signature_check(self):
        payload = self.root / "unsigned-payload"
        payload.mkdir()
        (payload / "fixture.txt").write_text("synthetic payload")
        package = self.root / "unsigned.pkg"
        subprocess.run(["/usr/bin/pkgbuild", "--root", str(payload), "--identifier", "com.aegis.fixture",
                        "--version", "1.0.0", "--install-location", "/Library/Application Support/AegisFixture",
                        str(package)], check=True, capture_output=True, timeout=30)
        self.env.update(AEGIS_MACOS_PKG_URL="", AEGIS_MACOS_PKG_PATH=str(package),
                        AEGIS_MACOS_PKG_SHA256=hashlib.sha256(package.read_bytes()).hexdigest())
        self.wrapper.write_text(self.wrapper.read_text().replace('"' + str(self.bin / "pkgutil") + '"', "/usr/sbin/pkgutil"))
        result, value = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value["status"], "package_signature_rejected")
        self.assert_no_install()


if __name__ == "__main__":
    unittest.main()
