"""Package real frozen artifacts; postinstall system operations remain isolated fixtures."""
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("AEGIS_MACOS_PACKAGE_BIN_DIR"),
                     "requires explicit ARM64 and x64 frozen artifacts")
class FrozenPackageTests(unittest.TestCase):
    def test_real_payload_and_relocated_install_use_embedded_runtime(self):
        with tempfile.TemporaryDirectory(prefix="aegis-frozen-pkg-") as temp:
            root = Path(temp).resolve()
            downloads = root / "public/downloads"
            downloads.mkdir(parents=True)
            (root / "scripts").mkdir()
            shutil.copy2(ROOT / "scripts/build-macos-pkg.sh", root / "scripts/build-macos-pkg.sh")
            for name in ("aegis_agent.py", "uninstall-aegis-macos.sh", "mdm-macos-compliance.sh", "MACOS-UNINSTALL.md", "aegis-policy.json", "aegis-security-baseline.md"):
                shutil.copy2(ROOT / "public/downloads" / name, downloads / name)
            for suffix in ("arm64", "x64"):
                name = "aegis-agent-darwin-" + suffix
                shutil.copy2(Path(os.environ["AEGIS_MACOS_PACKAGE_BIN_DIR"]) / name, downloads / name)
            env = {**os.environ, "AEGIS_PUBLIC_ORIGIN": "https://aegis.example.test"}
            result = subprocess.run(["/bin/sh", str(root / "scripts/build-macos-pkg.sh")], env=env,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            expanded = root / "expanded"
            subprocess.run(["/usr/sbin/pkgutil", "--expand-full", str(downloads / "aegis-agent-macos.pkg"), str(expanded)],
                           check=True, capture_output=True, timeout=90)
            payload = next(expanded.rglob("Payload"))
            app = payload / "Library/Application Support/AegisAgent"
            self.assertEqual(list(app.glob("*.py")), [])
            plist = plistlib.loads((payload / "Library/LaunchDaemons/com.aegis.agent.plist").read_bytes())
            self.assertEqual(plist["ProgramArguments"][0], "/Library/Application Support/AegisAgent/aegis-agent")
            for suffix in ("arm64", "x64"):
                name = "aegis-agent-darwin-" + suffix
                self.assertEqual((app / name).read_bytes(), (downloads / name).read_bytes())
            (app / "reporting.json").write_text(json.dumps({"report_url": "https://aegis.example.test/aegis/v1/reports", "report_token": "synthetic-fixture-" * 4}))
            old_policy = b'{"schema":"aegis.policy/v1","version":"fixture-retained"}\n'
            (app / "aegis-policy.json").write_bytes(old_policy)
            before_reporting = (app / "reporting.json").read_bytes()
            source = next(expanded.rglob("postinstall")).read_text()
            self.assertNotIn("python3", source)
            source = source.replace("/Library/", str(payload / "Library") + "/").replace("/Users/", str(payload / "Users") + "/")
            script = root / "postinstall"
            script.write_text(source)
            mock_bin = root / "bin"
            mock_bin.mkdir()
            mocks = {
                "uname": 'printf "%s\\n" "' + platform.machine() + '"',
                "ioreg": "printf '%s\\n' '\"IOPlatformSerialNumber\" = \"SYNTHETIC-LAB-SERIAL\"'",
                "launchctl": 'printf "%s\\n" "$*" >> "$AEGIS_TEST_CALLS"',
                "python3": 'printf called > "$AEGIS_TEST_PYTHON_CALLED"; exit 99',
            }
            for name in ("uname", "ioreg", "launchctl", "python3", "chown", "xattr", "osascript", "system_profiler", "hostname"):
                path = mock_bin / name
                path.write_text("#!/bin/sh\n" + mocks.get(name, "exit 0") + "\n")
                path.chmod(0o755)
            calls = root / "service-calls"
            env.update(PATH=str(mock_bin) + ":/usr/bin:/bin:/usr/sbin:/sbin", AEGIS_TEST_CALLS=str(calls),
                       AEGIS_TEST_PYTHON_CALLED=str(root / "python-called"))
            result = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)",
                                     "/bin/sh", str(script)], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "python-called").exists())
            self.assertEqual((app / "aegis-policy.json").read_bytes(), old_policy)
            self.assertEqual((app / "reporting.json").read_bytes(), before_reporting)
            self.assertIn("print system/com.aegis.agent", calls.read_text().splitlines())
            suffix = "arm64" if platform.machine() == "arm64" else "x64"
            self.assertEqual((app / "aegis-agent").read_bytes(), (downloads / ("aegis-agent-darwin-" + suffix)).read_bytes())
            for flag in ("--selftest", "--maintenance-selftest", "--diagnostics-selftest"):
                result = subprocess.run([str(app / "aegis-agent"), flag], env=env, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
