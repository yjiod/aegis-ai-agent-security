"""Synthetic configuration writes, including frozen root CI; no host credentials."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DL = Path(__file__).resolve().parents[1] / "public/downloads"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DL / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


maintenance = load("configuration_maintenance", "aegis_macos_maintenance.py")
with patch.dict(sys.modules, {"aegis_macos_maintenance": maintenance}):
    config = load("configuration", "aegis_macos_configuration.py")
agent = load("configuration_agent", "aegis_agent.py")


def fixture():
    return {"schema": "aegis.reporting/v1", "report_url": "https://aegis.example.test/reports",
            "report_token": "synthetic-token-" * 4, "signing_secret": "synthetic-secret-" * 4}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-config-fixture-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.path = self.root / "reporting.json"
        self.value = fixture()
        self.old = b'{"synthetic":"retained"}\n'
        self.path.write_bytes(self.old)
        self.path.chmod(0o600)

    def write(self):
        return config.write_config(self.root, self.value, owner=os.geteuid())

    def test_private_atomic_replace_does_not_change_policy_or_other_state(self):
        policy = self.root / "aegis-policy.json"
        policy.write_bytes(b"synthetic-policy")
        before = self.path.stat().st_ino
        self.assertEqual(self.write(), "applied")
        self.assertNotEqual(before, self.path.stat().st_ino)
        self.assertEqual(json.loads(self.path.read_text()), self.value)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(policy.read_bytes(), b"synthetic-policy")
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_first_configuration_requires_existing_install_directory(self):
        self.path.unlink()
        self.assertEqual(self.write(), "applied")
        with self.assertRaises(OSError): config.write_config(self.root / "missing", self.value, os.geteuid())
        self.assertFalse((self.root / "missing").exists())

    def test_invalid_input_preserves_existing_config_without_creating_lock(self):
        for change in ({"report_token": "short"}, {"signing_secret": self.value["report_token"]},
                       {"report_url": "http://aegis.example.test"}, {"report_url": "https://aegis.example.test:0"},
                       {"report_url": "https://aegis.example.test:99999"}, {"report_url": "https://user@aegis.example.test"},
                       {"report_url": "https://aegis.example.test?credential=fixture"},
                       {"report_token": "x" * 32 + "\n"}, {"signing_secret": "密" * 32}):
            with self.subTest(change=tuple(change)):
                with self.assertRaises(config.ConfigurationError):
                    config.write_config(self.root, {**self.value, **change}, os.geteuid())
                self.assertEqual(self.path.read_bytes(), self.old)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["reporting.json"])

    def test_write_sync_and_replace_failures_preserve_original_and_remove_temporary(self):
        for operation in ("fsync", "replace"):
            with self.subTest(operation=operation), patch.object(config.os, operation, side_effect=OSError("synthetic failure")):
                with self.assertRaises(OSError): self.write()
            self.assertEqual(self.path.read_bytes(), self.old)
            self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_parent_sync_failure_reports_applied_but_unconfirmed_durability(self):
        original = os.fsync
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("synthetic directory sync failure")
            return original(fd)
        with patch.object(config.os, "fsync", side_effect=sync):
            self.assertEqual(self.write(), "applied_durability_unconfirmed")
        self.assertEqual(json.loads(self.path.read_text()), self.value)

    def test_existing_links_fifo_and_unrestricted_permissions_refused(self):
        original = self.root / "original"
        self.path.rename(original)
        for kind in ("symlink", "hardlink", "fifo", "permissions"):
            with self.subTest(kind=kind):
                if kind == "symlink": self.path.symlink_to(original)
                elif kind == "hardlink": os.link(original, self.path)
                elif kind == "fifo": os.mkfifo(self.path)
                else: self.path.write_bytes(self.old); self.path.chmod(0o644)
                with self.assertRaises((OSError, config.ConfigurationError)): self.write()
                self.assertEqual(original.read_bytes(), self.old)
                self.path.unlink()

    def test_writable_or_linked_directory_and_wrong_owner_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(config.ConfigurationError): self.write()
        self.root.chmod(0o700)
        with self.assertRaises(config.ConfigurationError): config.write_config(self.root, self.value, os.geteuid() + 1)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): config.write_config(alias, self.value, os.geteuid())
        self.assertEqual(self.path.read_bytes(), self.old)

    def test_lock_contention_and_noncooperative_change_refuse_replacement(self):
        lock = os.open(self.root / ".reporting-config.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(config.ConfigurationError, "configuration_busy"): self.write()
        finally: os.close(lock)
        with patch.object(config, "existing_state", side_effect=[(1, 2, 3, 4), (1, 2, 3, 5)]):
            with self.assertRaisesRegex(config.ConfigurationError, "configuration_changed"): self.write()
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_lock_symlink_refused(self):
        (self.root / ".reporting-config.lock").symlink_to(self.path)
        with self.assertRaises(OSError): self.write()
        self.assertEqual(self.path.read_bytes(), self.old)

    @unittest.skipUnless(sys.platform == "darwin", "real Darwin extended ACL")
    def test_extended_acl_on_directory_or_config_is_not_silently_overwritten(self):
        for path in (self.root, self.path):
            subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True, capture_output=True)
            try:
                with self.assertRaisesRegex(config.ConfigurationError, "extended_acl_not_supported"): self.write()
                self.assertEqual(self.path.read_bytes(), self.old)
            finally: subprocess.run(["/bin/chmod", "-N", str(path)], check=True, capture_output=True)

    def test_main_never_prints_inputs_and_refuses_redirected_destination(self):
        env = {"AEGIS_REPORT_URL": self.value["report_url"], "AEGIS_REPORT_TOKEN": self.value["report_token"],
               "AEGIS_REPORT_SIGNING_SECRET": self.value["signing_secret"]}
        with patch.dict(os.environ, {**env, "AEGIS_REPORT_CONFIG": "/synthetic/other"}, clear=True), patch.object(sys, "platform", "darwin"), patch.object(os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(config.main(self.root), 1)
            self.assertEqual(json.loads(output.getvalue())["status"], "custom_destination_not_supported")
        with patch.dict(os.environ, env, clear=True), patch.object(sys, "platform", "darwin"), patch.object(os, "geteuid", return_value=0), patch.object(config, "write_config", return_value="applied") as write, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(config.main(self.root), 0)
            write.assert_called_once_with(self.root, self.value)
            for forbidden in (*self.value.values(), str(self.root)):
                self.assertNotIn(forbidden, output.getvalue())
            self.assertNotIn("AEGIS_REPORT_TOKEN", os.environ)

    @unittest.skipUnless(sys.platform == "darwin" and os.geteuid() == 0 and os.environ.get("AEGIS_FROZEN_AGENT"), "root CI and explicit frozen artifact")
    def test_frozen_configuration_without_network_or_external_runtime(self):
        binary = self.root / "aegis-agent"
        shutil.copy2(os.environ["AEGIS_FROZEN_AGENT"], binary)
        binary.chmod(0o755)
        env = {**os.environ, "PATH": "/nonexistent", "PYTHONHOME": "/nonexistent", "PYTHONPATH": "/nonexistent",
               "AEGIS_REPORT_CONFIG": str(self.path), "AEGIS_REPORT_URL": self.value["report_url"],
               "AEGIS_REPORT_TOKEN": self.value["report_token"], "AEGIS_REPORT_SIGNING_SECRET": self.value["signing_secret"]}
        profile = '(version 1)(allow default)(deny network*)(deny process-exec (require-not (literal (param "BINARY"))))'
        command = ["/usr/bin/sandbox-exec", "-D", "BINARY=" + str(binary), "-p", profile]
        result = subprocess.run(command + [str(binary), "--configure-reporting"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["applied"])
        self.assertEqual(json.loads(self.path.read_text()), self.value)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("synthetic", result.stdout + result.stderr)
        diagnostic = subprocess.run(command + [str(binary), "--diagnostics"], env=env, capture_output=True, text=True, timeout=30)
        self.assertTrue(json.loads(diagnostic.stdout)["AegisReportingConfigured"])
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(self.path)], check=True, capture_output=True)
        try:
            diagnostic = subprocess.run(command + [str(binary), "--diagnostics"], env=env, capture_output=True, text=True, timeout=30)
            self.assertFalse(json.loads(diagnostic.stdout)["AegisReportingConfigured"])
            self.assertNotIn("synthetic", diagnostic.stdout + diagnostic.stderr)
        finally: subprocess.run(["/bin/chmod", "-N", str(self.path)], check=True, capture_output=True)
        env["AEGIS_REPORT_TOKEN"] = "invalid"
        before = self.path.read_bytes()
        result = subprocess.run(command + [str(binary), "--configure-reporting"], env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["applied"])
        self.assertEqual(before, self.path.read_bytes())


class ConfigurationReadTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-config-read-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.path = self.root / "reporting.json"
        self.value = fixture()
        config.write_config(self.root, self.value, os.geteuid())

    def read(self, path=None, owner=None):
        return config.read_config(path or self.path, os.geteuid() if owner is None else owner)

    def test_reads_writer_snapshot_without_changing_state(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        self.assertEqual(self.read(), self.value)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})

    def test_maximum_escaped_credentials_roundtrip_through_writer_and_reader(self):
        value = {**self.value, "report_token": '"' * 4096, "signing_secret": '\\' * 4096}
        config.write_config(self.root, value, os.geteuid())
        self.assertGreater(self.path.stat().st_size, 16384)
        self.assertEqual(self.read(), value)

    def test_links_fifo_unsafe_modes_and_owner_are_refused(self):
        original = self.root / "original"
        self.path.rename(original)
        for kind in ("symlink", "hardlink", "fifo", "directory", "permissions"):
            with self.subTest(kind=kind):
                if kind == "symlink": self.path.symlink_to(original)
                elif kind == "hardlink": os.link(original, self.path)
                elif kind == "fifo": os.mkfifo(self.path)
                elif kind == "directory": self.path.mkdir()
                else: self.path.write_bytes(original.read_bytes()); self.path.chmod(0o644)
                with self.assertRaises((OSError, config.ConfigurationError)): self.read()
                if self.path.is_dir(): self.path.rmdir()
                else: self.path.unlink()
        original.rename(self.path)
        with self.assertRaises(config.ConfigurationError): self.read(owner=os.geteuid()+1)

    def test_linked_or_writable_parent_directory_is_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((OSError, config.ConfigurationError)): self.read(alias / "reporting.json")
        self.root.chmod(0o777)
        try:
            with self.assertRaises(config.ConfigurationError): self.read()
        finally: self.root.chmod(0o700)

    def test_duplicate_oversized_deep_and_non_utf8_json_are_fixed_errors(self):
        normal = json.dumps(self.value)
        for data in ((normal[:-1]+',"report_token":"replacement"}').encode(),
                     b' ' * (config.MAX_CONFIG_BYTES+1), b'[' * 2000 + b']' * 2000, b'\xff'):
            self.path.write_bytes(data)
            with self.assertRaises(config.ConfigurationError) as caught: self.read()
            self.assertNotIn("synthetic", str(caught.exception))
            self.assertNotIn(str(self.root), str(caught.exception))

    def test_mutation_during_read_is_refused(self):
        original = config.require_private_file
        calls = 0
        def check(fd, owner):
            nonlocal calls
            calls += 1
            if calls == 2:
                with self.path.open("ab") as stream: stream.write(b" ")
            return original(fd, owner)
        with patch.object(config, "require_private_file", side_effect=check):
            with self.assertRaisesRegex(config.ConfigurationError, "configuration_changed"): self.read()

    def test_reader_uses_same_url_and_credential_validation_as_writer(self):
        for change in ({"report_url": "https://aegis.example.test:99999"},
                       {"report_token": "x" * 32 + "\n"}, {"signing_secret": "密" * 32},
                       {"signing_secret": self.value["report_token"]}):
            value = {**self.value, **change}
            self.path.write_text(json.dumps(value))
            with self.assertRaises(config.ConfigurationError): self.read()
            with self.assertRaises(config.ConfigurationError): config.write_config(self.root, value, os.geteuid())

    @unittest.skipUnless(sys.platform == "darwin", "Mac runtime dispatch and actual ACLs")
    def test_client_reader_and_acl_rejection_use_the_shared_contract(self):
        with patch.dict(sys.modules, {"aegis_macos_configuration": config}):
            self.assertEqual(agent.load_reporting_config(self.path), self.value)
            for path in (self.path, self.root):
                subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True, capture_output=True)
                try:
                    with self.assertRaisesRegex(config.ConfigurationError, "extended_acl_not_supported"): self.read()
                    with self.assertRaises(ValueError): agent.load_reporting_config(self.path)
                finally: subprocess.run(["/bin/chmod", "-N", str(path)], check=True, capture_output=True)


class ConfigurationDispatchTests(unittest.TestCase):
    def test_capability_selftest_does_not_touch_files_or_consume_environment(self):
        with patch.object(config, "directory", side_effect=AssertionError("unexpected filesystem access")):
            self.assertTrue(config.selftest())

    def test_exclusive_modes_and_nonroot_refusal(self):
        with patch.dict(sys.modules, {"aegis_macos_configuration": config}), patch.object(sys, "platform", "darwin"), patch.object(config, "main", return_value=17) as main:
            with patch.object(sys, "argv", ["agent", "--configure-reporting"]): self.assertEqual(agent.main(), 17)
            main.reset_mock()
            for args in (["--configure-reporting", "--watch"], ["--configure-reporting=bad"], ["--", "--configure-reporting"], ["--configure-reporting", "--diagnostics"]):
                with patch.object(sys, "argv", ["agent", *args]): self.assertEqual(agent.main(), 2)
            main.assert_not_called()
        with patch.object(os, "geteuid", return_value=501), patch.object(config, "write_config") as write, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(config.main(Path("/unused")), 1)
            write.assert_not_called()

    def test_upload_receipt_is_bound_to_exact_credentials_and_url(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, "platform", "darwin"), patch.dict(sys.modules, {"aegis_macos_configuration": config}):
            path = Path(temp) / "receipt.json"
            agent.write_upload_status(path, value["report_url"], token=value["report_token"], signing_secret=value["signing_secret"])
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt["configuration_fingerprint"], config.config_fingerprint(value))
            for change in ({"report_token": "replacement-token-" * 4}, {"signing_secret": "replacement-secret-" * 4},
                           {"report_url": "https://aegis.example.test/new-path"}):
                self.assertNotEqual(receipt["configuration_fingerprint"], config.config_fingerprint({**value, **change}))
            for field in ("report_token", "signing_secret"): self.assertNotIn(value[field], path.read_text())


@unittest.skipUnless(sys.platform == "darwin", "Mac wrapper stat semantics")
class ConfigurationWrapperTests(unittest.TestCase):
    def test_trusted_wrapper_delegates_without_arguments_and_refuses_unsafe_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            library = root / "Library"
            app = library / "Application Support/AegisAgent"
            app.mkdir(parents=True)
            for path in (library, app.parent, app): path.chmod(0o755)
            fake_stat = root / "stat"
            fake_stat.write_text('#!/bin/sh\nif [ "$2" = "%u" ]; then printf 0; else exec /usr/bin/stat "$@"; fi\n')
            fake_stat.chmod(0o755)
            binary = app / "aegis-agent"
            calls = root / "calls"
            binary.write_text('#!/bin/sh\nprintf "%s %s\\n" "$#" "$1" >> "$AEGIS_TEST_CALLS"\ncase "$1" in\n--configuration-selftest) exit "${AEGIS_TEST_RC:-0}";;\n--configure-reporting) printf \'%s\\n\' \'{"fixture":true}\';;\n*) exit 2;;\nesac\n')
            binary.chmod(0o755)
            source = (DL / "aegis-configure-macos.sh").read_text().replace("/Library", str(library))
            source = source.replace("/usr/bin/id -u", "printf 0").replace("/usr/bin/stat", '"' + str(fake_stat) + '"')
            wrapper = root / "configure.sh"
            wrapper.write_text(source)
            env = {**os.environ, "PATH": "/nonexistent", "AEGIS_TEST_CALLS": str(calls)}
            def run(*args):
                return subprocess.run(["/bin/sh", str(wrapper), *args], env=env, capture_output=True, text=True, timeout=10)
            result = run()
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), {"fixture": True})
            self.assertEqual(calls.read_text().splitlines(), ["1 --configuration-selftest", "1 --configure-reporting"])
            calls.unlink()
            self.assertEqual(run("--extra").returncode, 2)
            wrapper.write_text(source.replace("printf 0", "printf 501"))
            self.assertEqual(run().returncode, 2)
            wrapper.write_text(source)
            binary.chmod(0o777)
            self.assertEqual(run().returncode, 1)
            self.assertFalse(calls.exists())
            binary.chmod(0o755)
            env["AEGIS_TEST_RC"] = "7"
            result = run()
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["applied"])
            self.assertEqual(calls.read_text().splitlines(), ["1 --configuration-selftest"])


if __name__ == "__main__":
    unittest.main()
