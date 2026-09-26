"""Opt-in real system-path/launchd validation on disposable GitHub-hosted Macs only.

Never enable this suite on a developer or pilot endpoint. The normal test command
skips before inspecting production paths. Test services only sleep or self-test;
they never scan users, enroll, upload or inject a baseline.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ENABLED = (sys.platform == 'darwin' and os.environ.get('AEGIS_DISPOSABLE_SYSTEM_TESTS') == 'github-hosted'
           and os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() == 0
           and bool(os.environ.get('AEGIS_FROZEN_AGENT')))
APP = Path('/Library/Application Support/AegisAgent')
LABELS = ('com.aegis.agent', 'com.company.aegis-agent')
JOURNAL = 'native-runtime-activation.json'
PROFILE = '''(version 1)
(allow default)
(deny network*)
(deny process-exec (require-all
  (require-not (literal (param "BINARY")))
  (require-not (literal "/bin/launchctl"))))
(deny file-read* (subpath "/Users") (subpath "/opt/homebrew") (subpath "/usr/local")
  (subpath "/Library/Frameworks/Python.framework") (subpath "/Library/Developer")
  (subpath "/Applications/Xcode.app") (literal "/usr/bin/python3"))
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(ENABLED, 'requires explicit disposable GitHub-hosted Mac root opt-in and frozen candidate')
class DisposableNativeActivationTests(unittest.TestCase):
    def launch(self, *args, capture=False):
        return subprocess.run(['/bin/launchctl', *args], stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, text=True, timeout=20, check=False)

    def setUp(self):
        # Refuse existing state rather than treating another installation as a
        # fixture. This must fail the opted-in gate, not silently skip coverage.
        self.assertEqual(self.launch('print', 'system').returncode, 0)
        self.assertFalse(APP.exists() or APP.is_symlink(), 'system installation already exists')
        self.plists = {label: Path('/Library/LaunchDaemons') / (label + '.plist') for label in LABELS}
        for label, path in self.plists.items():
            self.assertFalse(path.exists() or path.is_symlink(), 'system plist already exists')
            self.assertEqual(self.launch('print', 'system/' + label).returncode, 113, 'system service already exists or is unknown')
        APP.mkdir(mode=0o755)
        self.app_identity = (APP.stat().st_dev, APP.stat().st_ino)
        self.created_plists = {}
        self.addCleanup(self.cleanup_system_fixture)
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-disposable-native-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        # Compile a harmless old runtime so launchd has a real process to stop.
        source = root / 'previous.c'
        source.write_text('#include <unistd.h>\nint main(void) { sleep(300); return 0; }\n')
        self.canonical = APP / 'aegis-agent'
        compiled = subprocess.run(['/usr/bin/clang', str(source), '-o', str(self.canonical)],
                                  capture_output=True, timeout=60, check=False)
        self.assertEqual(compiled.returncode, 0, 'synthetic old runtime compilation failed')
        self.canonical.chmod(0o755)
        self.previous_digest = sha(self.canonical)
        self.arch = os.uname().machine
        self.assertIn(self.arch, ('arm64', 'x86_64'))
        name = 'aegis-agent-darwin-' + ('arm64' if self.arch == 'arm64' else 'x64')
        self.candidate = APP / name
        shutil.copyfile(os.environ['AEGIS_FROZEN_AGENT'], self.candidate)
        self.candidate.chmod(0o755)
        self.target_digest = sha(self.candidate)
        self.env = {**os.environ, 'PATH': '/nonexistent', 'PYTHONHOME': '/nonexistent', 'PYTHONPATH': '/nonexistent'}
        self.sandbox = ['/usr/bin/sandbox-exec', '-D', 'BINARY=' + str(self.candidate), '-p', PROFILE]
        denied = subprocess.run(self.sandbox + ['/usr/bin/true'], cwd=APP, env=self.env,
                                capture_output=True, timeout=20, check=False)
        self.assertNotEqual(denied.returncode, 0, 'process allowlist is not enforced')
        # Test the actual external interpreter as well, not just an unrelated executable.
        denied_python = subprocess.run(self.sandbox + ['/usr/bin/python3', '-c', 'raise SystemExit(0)'],
                                       cwd=APP, env=self.env, capture_output=True, timeout=20, check=False)
        self.assertNotEqual(denied_python.returncode, 0, 'external interpreter is not denied')
        result = self.native('--selftest')
        match = re.fullmatch(r'aegis-selftest-ok ([0-9]+\.[0-9]+\.[0-9]+)\s*', result.stdout)
        self.assertIsNotNone(match, 'frozen candidate self-test failed')
        self.version = match[1]
        (APP / 'aegis-runtime-manifest.json').write_text(json.dumps({
            'schema': 'aegis.macos-runtime/v1', 'agent_version': self.version,
            'files': {name: self.target_digest}}))
        (APP / 'aegis-runtime-manifest.json').chmod(0o644)

    def cleanup_system_fixture(self):
        # Only our exclusively created plists and directory can be removed.
        # A service that cannot be stopped makes cleanup fail and retains files.
        for label in self.created_plists:
            status = self.launch('print', 'system/' + label).returncode
            if status == 0:
                self.assertEqual(self.launch('bootout', 'system/' + label).returncode, 0)
            else:
                self.assertEqual(status, 113)
            self.assertEqual(self.launch('print', 'system/' + label).returncode, 113)
        for label, identity in self.created_plists.items():
            path = self.plists[label]
            info = path.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual((info.st_dev, info.st_ino), identity)
            path.unlink()
        info = APP.lstat()
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual((info.st_dev, info.st_ino), self.app_identity)
        shutil.rmtree(APP)

    def native(self, flag, expected=0):
        result = subprocess.run(self.sandbox + [str(self.candidate), flag], cwd=APP, env=self.env,
                                capture_output=True, text=True, timeout=45, check=False)
        # Do not attach arbitrary stdout/stderr to a failed CI assertion.
        self.assertEqual(result.returncode, expected, 'native maintenance command returned unexpected status: ' + flag)
        return result

    def status(self, flag, expected=0):
        value = json.loads(self.native(flag, expected).stdout)
        self.assertEqual(value['schema'], 'aegis.runtime-activation-result/v1')
        self.assertIs(value['health_verified'], False)
        return value['status']

    def journal(self):
        path = APP / JOURNAL
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return json.loads(path.read_text())

    def write_plist(self, label, args):
        path = self.plists[label]
        data = plistlib.dumps({'Label': label, 'ProgramArguments': args, 'RunAtLoad': True, 'KeepAlive': False})
        if label not in self.created_plists:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            info = os.fstat(fd)
            self.created_plists[label] = (info.st_dev, info.st_ino)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
        else:
            info = path.lstat()
            self.assertEqual((info.st_dev, info.st_ino), self.created_plists[label])
            path.write_bytes(data)
        self.assertEqual(self.launch('bootstrap', 'system', str(path)).returncode, 0, 'fixture bootstrap failed')

    def running_pid(self, label):
        for _ in range(30):
            result = self.launch('print', 'system/' + label, capture=True)
            if result.returncode == 0:
                match = re.search(r'(?m)^\s*pid = ([1-9][0-9]*)\s*$', result.stdout)
                if match:
                    return int(match[1])
            time.sleep(0.1)
        self.fail('synthetic service did not start')

    def process_gone(self, pid):
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        self.fail('old synthetic process survived service removal')

    def test_real_stop_replace_restore_and_registration_without_external_python(self):
        pids = []
        for label in LABELS:
            self.write_plist(label, [str(self.canonical)])
            pids.append(self.running_pid(label))
        # This is the unmodified CLI and fixed system destination, not a source
        # function, relocated path, fake launchctl or replacement helper.
        with self.canonical.open('rb') as original_inode:
            self.assertEqual(self.status('--stage-native-runtime'), 'staged')
            self.assertEqual(hashlib.sha256(original_inode.read()).hexdigest(), self.previous_digest)
        for pid in pids:
            self.process_gone(pid)
        for label in LABELS:
            self.assertEqual(self.launch('print', 'system/' + label).returncode, 113)
        self.assertEqual(sha(self.canonical), self.target_digest)
        self.assertEqual(sha(APP / '.native-runtime-previous'), self.previous_digest)
        self.assertEqual(self.journal()['status'], 'staged')
        self.assertEqual(self.status('--confirm-native-runtime', expected=1), 'service_registration_unconfirmed')
        self.assertEqual(self.status('--stage-native-runtime'), 'staged')
        self.assertEqual(sha(APP / '.native-runtime-previous'), self.previous_digest)
        self.assertEqual(self.status('--restore-native-runtime'), 'restored_activation_pending')
        self.assertEqual(sha(self.canonical), self.previous_digest)
        for label in LABELS:
            self.assertEqual(self.launch('print', 'system/' + label).returncode, 113)
        # Reinstall and register a memory-only self-test job. No production scan.
        self.assertEqual(self.status('--stage-native-runtime'), 'staged')
        self.write_plist(LABELS[0], [str(self.canonical), '--runtime-activation-selftest'])
        self.assertEqual(self.status('--confirm-native-runtime'), 'service_registered')
        self.assertEqual(self.journal()['status'], 'service_registered')
        health = json.loads(self.native('--diagnostics').stdout)
        self.assertFalse(health['AegisReportingHealthy'])
        self.assertFalse(health['AegisScanRecent'])
        self.assertEqual(self.status('--restore-native-runtime'), 'restored_activation_pending')
        self.assertEqual(self.launch('print', 'system/' + LABELS[0]).returncode, 113)
        self.assertEqual(sha(self.canonical), self.previous_digest)
        evidence = {'schema': 'aegis.disposable-native-maintenance/v1', 'architecture': self.arch,
                    'agent_version': self.version, 'candidate_sha256': self.target_digest,
                    'fixed_system_path': True, 'actual_launchd_and_old_process_exit': True,
                    'native_atomic_stage_and_restore': True, 'registration_confirmed': True,
                    'external_executables_denied_except_candidate_and_launchctl': True,
                    'user_directory_reads_denied': True, 'network_denied': True,
                    'full_installer_lifecycle_verified': False, 'production_health_verified': False}
        output = os.environ.get('AEGIS_NATIVE_VALIDATION_RESULT')
        self.assertTrue(output, 'evidence output is required in the opted-in gate')
        Path(output).write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n')
        Path(output).chmod(0o644)


if __name__ == '__main__':
    unittest.main()
