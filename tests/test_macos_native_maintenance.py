"""Maintenance dispatch and wrapper boundaries; no production uninstall is run."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DL = ROOT / "public/downloads"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DL / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


agent = load("native_maintenance_agent", "aegis_agent.py")
maintenance = load("native_maintenance_helper", "aegis_macos_maintenance.py")


class MaintenanceDispatchTests(unittest.TestCase):
    def dispatch(self, args, platform="darwin"):
        with patch.object(sys, "argv", ["aegis-agent", *args]), patch.object(sys, "platform", platform):
            return agent.main()

    def test_exclusive_modes_delegate_without_reusing_process_arguments(self):
        with patch.dict(sys.modules, {"aegis_macos_maintenance": maintenance}), patch.object(maintenance, "main", return_value=17) as entry:
            for flag, expected in (("--maintenance-selftest", ["--selftest"]), ("--uninstall-system", [])):
                self.assertEqual(self.dispatch([flag]), 17)
                entry.assert_called_with(expected)

    def test_mixed_duplicate_and_value_arguments_cannot_reach_maintenance(self):
        with patch.dict(sys.modules, {"aegis_macos_maintenance": maintenance}), patch.object(maintenance, "main") as entry:
            for args in (["--uninstall-system", "--selftest"], ["--uninstall-system", "--watch"],
                         ["--uninstall-system", "/tmp"], ["--uninstall-system", "--uninstall-system"],
                         ["--uninstall-system=true"], ["--maintenance-selftest", "--uninstall-system"],
                         ["--", "--uninstall-system"]):
                with self.subTest(args=args):
                    self.assertEqual(self.dispatch(args), 2)
            entry.assert_not_called()

    def test_non_mac_and_missing_module_fail_before_system_access(self):
        with patch.dict(sys.modules, {"aegis_macos_maintenance": None}):
            self.assertEqual(self.dispatch(["--uninstall-system"], "win32"), 2)
            self.assertEqual(self.dispatch(["--uninstall-system"]), 1)

    def test_helper_explicit_selftest_never_opens_directories(self):
        with patch.object(maintenance, "directory", side_effect=AssertionError("unexpected filesystem access")), patch.object(sys, "argv", ["agent", "--uninstall-system"]):
            self.assertEqual(maintenance.main(["--selftest"]), 0)

    @unittest.skipUnless(hasattr(os, "geteuid"), "POSIX permissions")
    def test_helper_refuses_unprivileged_uninstall(self):
        with patch.object(sys, "platform", "darwin"), patch.object(os, "geteuid", return_value=501), patch.object(maintenance, "directory") as directory:
            self.assertEqual(maintenance.main([]), 2)
            directory.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Mac self-test includes maintenance")
    def test_client_selftest_refuses_broken_maintenance(self):
        with patch.dict(sys.modules, {"aegis_macos_maintenance": maintenance}), patch.object(maintenance, "selftest", return_value=False):
            self.assertEqual(agent.run_selftest(), 1)


@unittest.skipUnless(sys.platform == "darwin", "Mac stat semantics")
class UninstallWrapperTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-native-maintenance-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        library = self.root / "Library"
        self.app = library / "Application Support/AegisAgent"
        self.app.mkdir(parents=True)
        for directory in (library, self.app.parent, self.app):
            directory.chmod(0o755)
        self.calls = self.root / "calls"
        stat = self.root / "stat-fixture"
        stat.write_text('#!/bin/sh\nif [ "$2" = "%u" ]; then echo "${AEGIS_TEST_OWNER:-0}"; else exec /usr/bin/stat "$@"; fi\n')
        stat.chmod(0o755)
        self.wrapper = self.root / "uninstall.sh"
        source = (DL / "uninstall-aegis-macos.sh").read_text()
        source = source.replace("/Library", str(library)).replace("/usr/bin/id -u", "printf 0")
        source = source.replace("/usr/bin/stat", '"' + str(stat) + '"')
        self.wrapper.write_text(source)
        self.env = {**os.environ, "AEGIS_TEST_CALLS": str(self.calls)}
        self.binary = self.app / "aegis-agent"
        self.binary.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$AEGIS_TEST_CALLS"\ncase "$1" in\n--maintenance-selftest) exit "${AEGIS_TEST_SELFTEST_RC:-0}";;\n--uninstall-system) exit "${AEGIS_TEST_UNINSTALL_RC:-0}";;\n*) exit 2;;\nesac\n')
        self.binary.chmod(0o755)

    def run_wrapper(self):
        return subprocess.run(["/bin/sh", str(self.wrapper)], env=self.env, capture_output=True, text=True, timeout=20)

    def test_wrapper_checks_capability_then_preserves_uninstall_failure(self):
        self.env["AEGIS_TEST_UNINSTALL_RC"] = "17"
        self.assertEqual(self.run_wrapper().returncode, 17)
        self.assertEqual(self.calls.read_text().splitlines(), ["--maintenance-selftest", "--uninstall-system"])

    def test_failed_capability_never_starts_uninstall(self):
        self.env["AEGIS_TEST_SELFTEST_RC"] = "2"
        self.assertEqual(self.run_wrapper().returncode, 1)
        self.assertEqual(self.calls.read_text().splitlines(), ["--maintenance-selftest"])

    def test_missing_binary_does_not_fall_back_to_legacy_helper(self):
        self.binary.rename(self.app / "aegis-maintenance")
        (self.app / "aegis_macos_maintenance.py").write_text('raise RuntimeError("must not run")\n')
        self.assertEqual(self.run_wrapper().returncode, 1)
        self.assertFalse(self.calls.exists())

    def test_untrusted_binary_or_directory_is_refused_before_execution(self):
        for target in (self.binary, self.app):
            with self.subTest(target=target.name):
                target.chmod(0o777)
                self.assertEqual(self.run_wrapper().returncode, 1)
                self.assertFalse(self.calls.exists())
                target.chmod(0o755)
        self.env["AEGIS_TEST_OWNER"] = "501"
        self.assertEqual(self.run_wrapper().returncode, 1)
        self.assertFalse(self.calls.exists())

    def test_symlinked_binary_is_refused(self):
        target = self.root / "outside-agent"
        self.binary.rename(target)
        self.binary.symlink_to(target)
        self.assertEqual(self.run_wrapper().returncode, 1)
        self.assertFalse(self.calls.exists())


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("AEGIS_FROZEN_AGENT"), "requires an explicitly supplied frozen Mac artifact")
class FrozenMaintenanceTests(unittest.TestCase):
    @unittest.skipUnless(Path("/usr/bin/sandbox-exec").is_file(), "requires macOS sandbox-exec")
    def test_selftest_under_denied_external_runtime_access(self):
        with tempfile.TemporaryDirectory(prefix="aegis-frozen-sandbox-") as temp:
            binary = Path(temp).resolve() / "aegis-agent"
            shutil.copy2(os.environ["AEGIS_FROZEN_AGENT"], binary)
            binary.chmod(0o755)
            profile = '''(version 1)
(allow default)
(deny network*)
(deny process-exec (require-not (literal (param "BINARY"))))
(deny file-read* (subpath "/opt/homebrew") (subpath "/usr/local")
  (subpath "/Library/Frameworks/Python.framework")
  (subpath "/Library/Developer") (subpath "/Applications/Xcode.app")
  (literal "/usr/bin/python3"))
'''
            command = ["/usr/bin/sandbox-exec", "-D", "BINARY=" + str(binary), "-p", profile]
            # Verify the profile actively denies another executable. This is
            # sandbox evidence, not a claim that the host has no Python installed.
            denied = subprocess.run(command + ["/bin/sh", "-c", "exit 0"], capture_output=True, timeout=20)
            self.assertNotEqual(denied.returncode, 0)
            for flag in ("--selftest", "--maintenance-selftest", "--diagnostics-selftest", "--configuration-selftest"):
                result = subprocess.run(command + [str(binary), flag], cwd=temp, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_binary_is_needed_and_external_python_environment_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="aegis-frozen-maintenance-") as temp:
            root = Path(temp)
            binary = root / "aegis-agent"
            shutil.copy2(os.environ["AEGIS_FROZEN_AGENT"], binary)
            binary.chmod(0o755)
            poison = root / "external"
            poison.mkdir()
            for name in ("sitecustomize.py", "aegis_macos_maintenance.py", "aegis_self_update.py", "aegis_macos_diagnostics.py", "aegis_macos_configuration.py"):
                (poison / name).write_text('raise RuntimeError("external module must not load")\n')
                (root / name).write_text('raise RuntimeError("sibling module must not load")\n')
            env = {**os.environ, "PATH": "/nonexistent", "PYTHONHOME": str(poison), "PYTHONPATH": str(poison),
                   "PYTHONUSERBASE": str(poison), "PYTHONSTARTUP": str(poison / "sitecustomize.py")}
            for flag, marker in (("--selftest", "aegis-selftest-ok"), ("--maintenance-selftest", "aegis-maintenance-selftest-ok"), ("--diagnostics-selftest", "aegis-diagnostics-selftest-ok"), ("--configuration-selftest", "aegis-configuration-selftest-ok")):
                result = subprocess.run([str(binary), flag], cwd=poison, env=env, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(marker, result.stdout)
            # Mixed flags must refuse before real service/file access, even as root.
            result = subprocess.run([str(binary), "--uninstall-system", "--selftest"], env=env, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
