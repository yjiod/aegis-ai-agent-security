"""Real pkgbuild/expansion with isolated postinstall fixtures; never installs on the host.

launchd, enrollment and hardware discovery are test doubles. These checks do not
claim privileged installation, daemon health, signing or native CPU execution.
"""
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ("aegis_agent.py", "aegis_self_update.py", "aegis-policy.json", "aegis-security-baseline.md")
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
        cls.package = cls.build_package("python")
        # Shell fixtures validate selection only; they are not native artifacts.
        for arch in ("arm64", "x64"):
            binary = cls.downloads / f"aegis-agent-darwin-{arch}"
            binary.write_text('#!/bin/sh\n# fixture: ' + arch + '\n[ "$1" = --selftest ]\n')
            binary.chmod(0o755)
        cls.native_package = cls.build_package("native-fixtures")

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
                    "AEGIS_TEST_CALLS": str(self.calls), "AEGIS_TEST_ARCH": "arm64"}
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

    def prepare(self, native=False, enrolled=True):
        payload, script = self.native_package if native else self.package
        shutil.copytree(payload, self.target, dirs_exist_ok=True)
        self.app = self.target / "Library/Application Support/AegisAgent"
        self.policy = self.app / "aegis-policy.json"
        self.reporting = self.app / "reporting.json"
        if enrolled:
            self.reporting.write_text(json.dumps({"report_url": ORIGIN + "/aegis/v1/reports", "report_token": "fixture-" * 8}))
            self.reporting.chmod(0o600)
        # Relocate the extracted script for this test only. No production override
        # allows callers to redirect a privileged installation.
        source = script.read_text()
        source = source.replace("/Library/", str(self.target / "Library") + "/")
        source = source.replace("/Users/", str(self.target / "Users") + "/")
        self.script = self.case / "postinstall"
        self.script.write_text(source)
        return payload

    def run_postinstall(self):
        return subprocess.run(["sh", str(self.script)], env=self.env, capture_output=True, text=True, errors="backslashreplace", timeout=30)

    def launch_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_payload_has_factory_policy_and_complete_script_runtime(self):
        self.prepare()
        self.assertFalse(self.policy.exists())
        self.assertEqual((self.app / "aegis-policy.factory.json").read_bytes(), (ROOT / "public/downloads/aegis-policy.json").read_bytes())
        for name in ("aegis_agent.py", "aegis_self_update.py"):
            self.assertEqual((self.app / name).read_bytes(), (ROOT / "public/downloads" / name).read_bytes())
        # Execute the actual packaged runtime, without scanning, network or writes.
        result = subprocess.run([sys.executable, str(self.app / "aegis_agent.py"), "--selftest"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)

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
        interpreter = plist["ProgramArguments"][0]
        result = subprocess.run([interpreter, str(self.app / "aegis_agent.py"), "--selftest"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)

    def test_new_install_initializes_factory_policy(self):
        self.prepare()
        self.assertEqual(self.run_postinstall().returncode, 0)
        self.assertEqual(self.policy.read_bytes(), (self.app / "aegis-policy.factory.json").read_bytes())

    def test_enrollment_failure_is_deferred_but_service_registration_is_checked(self):
        self.prepare(enrolled=False)
        # Only this test replaces enrollment; no network requests leave the fixture.
        (self.app / "aegis_agent.py").write_text('import sys\nsys.exit(0 if sys.argv[1] == "--selftest" else 3)\n')
        result = self.run_postinstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.app / "enroll-pending").exists())
        self.assertIn(["print", "system/com.aegis.agent"], self.launch_calls())

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
        (self.app / "aegis_agent.py").write_text("raise SystemExit(7)\n")
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
        self.prepare(native=True)
        for arch, suffix in (("arm64", "arm64"), ("x86_64", "x64")):
            with self.subTest(arch=arch):
                self.env["AEGIS_TEST_ARCH"] = arch
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
        self.prepare(native=True)
        (self.app / "aegis-agent-darwin-arm64").unlink()
        shutil.copy2(self.app / "aegis-agent-darwin-x64", self.app / "aegis-agent")
        self.assertNotEqual(self.run_postinstall().returncode, 0)
        self.assertEqual(self.launch_calls(), [])

    def test_script_package_does_not_select_previous_native_runtime(self):
        self.prepare()
        stale = self.app / "aegis-agent-darwin-arm64"
        stale.write_text("#!/bin/sh\nexit 77\n")
        stale.chmod(0o755)
        self.assertEqual(self.run_postinstall().returncode, 0)
        self.assertFalse((self.app / "aegis-agent").exists())


if __name__ == "__main__":
    unittest.main()
