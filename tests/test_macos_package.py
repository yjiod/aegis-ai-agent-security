"""Real pkgbuild/expansion with isolated postinstall fixtures; never installs on the host.

launchd, enrollment and hardware discovery are test doubles. These checks do not
claim privileged installation, daemon health or signing. Compiled native test
executables exercise packaging; they are not the production frozen client.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ("aegis_agent.py", "aegis_self_update.py", "aegis_macos_maintenance.py", "uninstall-aegis-macos.sh", "aegis-configure-macos.sh", "mdm-macos-compliance.sh", "MACOS-UNINSTALL.md", "aegis-policy.json", "aegis-security-baseline.md")
ORIGIN = "https://aegis.example.test"


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("pkgbuild"), "requires macOS pkgbuild")
class MacPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="aegis-pkg-tests-")
        cls.addClassCleanup(cls.work.cleanup)
        cls.root = Path(cls.work.name)
        cls.repo = cls.root / "repo"
        cls.downloads = cls.repo / "public/downloads"
        cls.downloads.mkdir(parents=True)
        (cls.repo / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/build-macos-pkg.sh", cls.repo / "scripts/build-macos-pkg.sh")
        for name in RUNTIME:
            shutil.copy2(ROOT / "public/downloads" / name, cls.downloads / name)
        # Small native fixtures, with no scan/enrollment/system side effects.
        fixture = cls.root / "fixture.c"
        fixture.write_text("""#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc == 9 && strcmp(argv[1], "--install-config") == 0) return getenv("AEGIS_TEST_ENROLL_OK") ? 0 : 3;
  if (argc != 2) return 3;
  if (strcmp(argv[1], "--selftest") == 0) return getenv("AEGIS_TEST_RUNTIME_FAIL") ? 7 : 0;
  if (strcmp(argv[1], "--prepare-legacy-services") == 0) return getenv("AEGIS_TEST_MIGRATION_FAIL") ? 9 : 0;
  if (strcmp(argv[1], "--service-migration-selftest") == 0) return 0;
  if (strcmp(argv[1], "--maintenance-selftest") == 0) return getenv("AEGIS_TEST_MAINTENANCE_FAIL") ? 7 : 0;
  return 3;
}
""")
        for suffix, arch in (("arm64", "arm64"), ("x64", "x86_64")):
            subprocess.run(["/usr/bin/clang", "-target", arch + "-apple-macos14", str(fixture),
                            "-o", str(cls.downloads / ("aegis-agent-darwin-" + suffix))],
                           check=True, capture_output=True, timeout=60)
        cls.package = cls.build_package("native-fixtures")

    @classmethod
    def build_package(cls, name):
        result = subprocess.run(["sh", str(cls.repo / "scripts/build-macos-pkg.sh")],
                                env={**os.environ, "AEGIS_PUBLIC_ORIGIN": ORIGIN},
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError("fixture package build failed: " + result.stderr)
        expanded = cls.root / name
        subprocess.run(["pkgutil", "--expand-full", str(cls.downloads / "aegis-agent-macos.pkg"), str(expanded)],
                       check=True, capture_output=True, timeout=60)
        payloads = list(expanded.rglob("Payload"))
        scripts = list(expanded.rglob("postinstall"))
        if len(payloads) != 1 or len(scripts) != 1:
            raise AssertionError("unexpected package layout")
        return payloads[0], scripts[0]

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=self.root))
        self.target = self.case / "target"
        self.bin = self.case / "bin"
        self.bin.mkdir()
        self.calls = self.case / "calls.jsonl"
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "AEGIS_TEST_CALLS": str(self.calls), "AEGIS_TEST_ARCH": platform.machine()}
        mock = '''#!/usr/bin/env python3
import json, os, pathlib, sys
command = pathlib.Path(sys.argv[0]).name
if command == "launchctl":
    with open(os.environ["AEGIS_TEST_CALLS"], "a") as stream:
        stream.write(json.dumps(sys.argv[1:]) + "\\n")
    sys.exit(int(os.environ.get("AEGIS_TEST_FAIL_" + sys.argv[1].upper(), "0")))
if command == "ioreg":
    print('"IOPlatformSerialNumber" = "SYNTHETIC-LAB-SERIAL"')
if command == "uname":
    print(os.environ["AEGIS_TEST_ARCH"])
'''
        for command in ("launchctl", "ioreg", "system_profiler", "hostname", "uname", "chown", "xattr", "osascript"):
            path = self.bin / command
            path.write_text(mock)
            path.chmod(0o755)

    def prepare(self, enrolled=True):
        if enrolled: self.env["AEGIS_TEST_ENROLL_OK"] = "1"
        else: self.env.pop("AEGIS_TEST_ENROLL_OK", None)
        payload, script = self.package
        shutil.copytree(payload, self.target, dirs_exist_ok=True)
        self.app = self.target / "Library/Application Support/AegisAgent"
        self.policy = self.app / "aegis-policy.json"
        self.reporting = self.app / "reporting.json"
        if enrolled:
            self.reporting.write_text(json.dumps({"schema": "aegis.reporting/v1", "report_url": ORIGIN + "/aegis/v1/reports", "report_token": "fixture-" * 8, "signing_secret": "synthetic-signing-" * 4}))
            self.reporting.chmod(0o600)
        # Relocate the extracted script for this test only. No production override
        # allows callers to redirect a privileged installation.
        source = script.read_text()
        source = source.replace("/Users/*/Library/", "__AEGIS_USER_LIBRARY__")
        source = source.replace("/Library/", str(self.target / "Library") + "/")
        source = source.replace("/Users/", str(self.target / "Users") + "/")
        source = source.replace("__AEGIS_USER_LIBRARY__", str(self.target / "Users") + "/*/Library/")
        self.script = self.case / "postinstall"
        self.script.write_text(source)
        return payload

    def run_postinstall(self):
        return subprocess.run(["sh", str(self.script)], env=self.env, capture_output=True, text=True, errors="backslashreplace", timeout=30)

    def launch_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_payload_has_factory_policy_and_no_external_python_runtime(self):
        self.prepare()
        self.assertFalse(self.policy.exists())
        self.assertEqual((self.app / "aegis-policy.factory.json").read_bytes(), (ROOT / "public/downloads/aegis-policy.json").read_bytes())
        for name in ("aegis_agent.py", "aegis_self_update.py", "aegis_macos_maintenance.py"):
            self.assertFalse((self.app / name).exists())
        self.assertEqual((self.app / "uninstall-aegis-macos.sh").read_bytes(), (ROOT / "public/downloads/uninstall-aegis-macos.sh").read_bytes())
        result = subprocess.run(["sh", str(self.app / "uninstall-aegis-macos.sh"), "--unexpected"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)

    def test_package_inventory_matches_both_runtimes_and_baseline(self):
        self.prepare()
        manifest = json.loads((self.app / "aegis-runtime-manifest.json").read_text())
        self.assertEqual(manifest["schema"], "aegis.macos-runtime/v1")
        self.assertEqual(set(manifest["files"]), {"aegis-agent-darwin-arm64", "aegis-agent-darwin-x64", "aegis-security-baseline.md"})
        for name, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((self.app / name).read_bytes()).hexdigest(), digest)
        self.assertEqual((self.app / "mdm-macos-compliance.sh").read_bytes(), (ROOT / "public/downloads/mdm-macos-compliance.sh").read_bytes())

    def test_upgrade_payload_and_postinstall_preserve_active_state(self):
        payload = self.prepare()
        active = b'{"schema":"aegis.policy/v1","version":"lab-current"}\n'
        self.policy.write_bytes(active)
        self.policy.chmod(0o600)
        reporting = self.reporting.read_bytes()
        # Overlay the real payload, reproducing the Installer's replacement phase.
        shutil.copytree(payload, self.target, dirs_exist_ok=True)
        result = self.run_postinstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.policy.read_bytes(), active)
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.reporting.read_bytes(), reporting)
        self.assertFalse((self.app / "enroll-pending").exists())
        self.assertIn(["print", "system/com.aegis.agent"], self.launch_calls())
        plist = plistlib.loads((self.target / "Library/LaunchDaemons/com.aegis.agent.plist").read_bytes())
        executable = plist["ProgramArguments"][0]
        self.assertEqual(executable, "/Library/Application Support/AegisAgent/aegis-agent")
        result = subprocess.run([str(self.app / "aegis-agent"), "--selftest"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)

    def test_new_install_initializes_factory_policy(self):
        self.prepare()
        self.assertEqual(self.run_postinstall().returncode, 0)
        self.assertEqual(self.policy.read_bytes(), (self.app / "aegis-policy.factory.json").read_bytes())

    def test_native_without_embedded_maintenance_cannot_register_service(self):
        self.prepare()
        self.env["AEGIS_TEST_MAINTENANCE_FAIL"] = "1"
        (self.app / "aegis-agent").write_bytes(b"previous-client")
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("embedded maintenance", result.stderr)
        self.assertEqual((self.app / "aegis-agent").read_bytes(), b"previous-client")
        self.assertEqual(self.launch_calls(), [])

    def test_enrollment_failure_is_deferred_but_service_registration_is_checked(self):
        self.prepare(enrolled=False)
        # The compiled fixture refuses --install-config without network access.
        result = self.run_postinstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.app / "enroll-pending").exists())
        self.assertIn(["print", "system/com.aegis.agent"], self.launch_calls())

    def test_legacy_preparation_failure_prevents_canonical_replacement_and_service_start(self):
        self.prepare()
        legacy = self.target / "Users/synthetic-user/Library/LaunchAgents/com.aegis.agent.plist"
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b"synthetic legacy configuration")
        canonical = self.app / "aegis-agent"
        canonical.write_bytes(b"synthetic existing runtime")
        self.env["AEGIS_TEST_MIGRATION_FAIL"] = "1"
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(canonical.read_bytes(), b"synthetic existing runtime")
        self.assertEqual(legacy.read_bytes(), b"synthetic legacy configuration")
        self.assertEqual(self.launch_calls(), [])

    def test_service_registration_failure_is_not_install_success(self):
        self.prepare()
        self.env["AEGIS_TEST_FAIL_BOOTSTRAP"] = "5"
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registration failed", result.stderr)
        self.assertFalse(any(call[0] == "load" for call in self.launch_calls()))

    def test_unconfirmed_service_is_not_install_success(self):
        self.prepare()
        self.env["AEGIS_TEST_FAIL_PRINT"] = "3"
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not be confirmed", result.stderr)

    def test_broken_runtime_fails_before_service_mutation(self):
        self.prepare()
        self.env["AEGIS_TEST_RUNTIME_FAIL"] = "1"
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.launch_calls(), [])

    def test_active_policy_symlink_is_refused(self):
        self.prepare()
        outside = self.case / "unmanaged.json"
        outside.write_bytes(b"unchanged")
        self.policy.symlink_to(outside)
        self.assertNotEqual(self.run_postinstall().returncode, 0)
        self.assertEqual(outside.read_bytes(), b"unchanged")
        self.assertEqual(self.launch_calls(), [])

    def test_native_architecture_selection(self):
        self.prepare()
        suffix = "arm64" if platform.machine() == "arm64" else "x64"
        self.assertEqual(self.run_postinstall().returncode, 0)
        self.assertEqual((self.app / "aegis-agent").read_bytes(), (self.app / f"aegis-agent-darwin-{suffix}").read_bytes())

    def test_partial_native_package_is_rejected(self):
        binary = self.downloads / "aegis-agent-darwin-x64"
        saved = binary.read_bytes()
        binary.unlink()
        try:
            result = subprocess.run(["sh", str(self.repo / "scripts/build-macos-pkg.sh")], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires both ARM64 and x64", result.stderr)
        finally:
            binary.write_bytes(saved)
            binary.chmod(0o755)

    def test_missing_native_payload_does_not_fall_back_to_stale_binary(self):
        self.prepare()
        (self.app / ("aegis-agent-darwin-arm64" if platform.machine() == "arm64" else "aegis-agent-darwin-x64")).unlink()
        (self.app / "aegis-agent").write_bytes(b"previous-client")
        self.assertNotEqual(self.run_postinstall().returncode, 0)
        self.assertEqual(self.launch_calls(), [])

    def test_no_payload_cannot_build_a_python_package(self):
        saved = {name: (self.downloads / name).read_bytes() for name in ("aegis-agent-darwin-arm64", "aegis-agent-darwin-x64")}
        try:
            for name in saved:
                (self.downloads / name).unlink()
            result = subprocess.run(["sh", str(self.repo / "scripts/build-macos-pkg.sh")], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires both", result.stderr)
        finally:
            for name, data in saved.items():
                (self.downloads / name).write_bytes(data)
                (self.downloads / name).chmod(0o755)

    def test_script_wrong_architecture_and_symlink_are_refused_by_builder(self):
        binary = self.downloads / "aegis-agent-darwin-arm64"
        saved = binary.read_bytes()
        try:
            for content in (b"#!/bin/sh\nexit 0\n", (self.downloads / "aegis-agent-darwin-x64").read_bytes()):
                binary.write_bytes(content)
                result = subprocess.run(["sh", str(self.repo / "scripts/build-macos-pkg.sh")], capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
            binary.unlink()
            binary.symlink_to(self.downloads / "aegis-agent-darwin-x64")
            result = subprocess.run(["sh", str(self.repo / "scripts/build-macos-pkg.sh")], capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
        finally:
            if binary.is_symlink():
                binary.unlink()
            binary.write_bytes(saved)
            binary.chmod(0o755)

    def test_installer_rejects_script_payload_even_with_stale_native_client(self):
        self.prepare()
        suffix = "arm64" if platform.machine() == "arm64" else "x64"
        (self.app / ("aegis-agent-darwin-" + suffix)).write_text("#!/bin/sh\nexit 0\n")
        (self.app / "aegis-agent").write_bytes(b"previous-client")
        result = self.run_postinstall()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.launch_calls(), [])
        self.assertEqual((self.app / "aegis-agent").read_bytes(), b"previous-client")

    def test_missing_source_version_cannot_become_a_zero_version_package(self):
        source = self.downloads / "aegis_agent.py"
        saved = source.read_bytes()
        package = (self.downloads / "aegis-agent-macos.pkg").read_bytes()
        try:
            for content in (b"# missing metadata\n", b'AGENT_VERSION = "invalid"\n'):
                source.write_bytes(content)
                result = subprocess.run(["sh", str(self.repo / "scripts/build-macos-pkg.sh")], capture_output=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((self.downloads / "aegis-agent-macos.pkg").read_bytes(), package)
        finally:
            source.write_bytes(saved)


if __name__ == "__main__":
    unittest.main()
