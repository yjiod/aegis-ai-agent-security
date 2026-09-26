"""Synthetic runtime bytes and service doubles; never operate the host daemon."""
import fcntl
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'public/downloads'))
import aegis_macos_runtime_activation as activation
import aegis_macos_maintenance as maintenance
import aegis_macos_diagnostics as diagnostics


class Services:
    def __init__(self):
        self.stops = []
        self.registered = False
        self.fail_stop = False
        self.on_stop = None
        self.legacy = 113

    def stop(self, domain, label):
        self.stops.append((domain, label))
        if self.fail_stop:
            raise maintenance.MaintenanceError('service_stop_failed')
        if self.on_stop:
            self.on_stop()
        self.registered = False

    def run(self, args):
        return self.legacy if args[-1].endswith('com.company.aegis-agent') else (0 if self.registered else 113)


class RuntimeActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name).resolve() / "app"
        self.app.mkdir()
        self.owner = os.getuid()
        self.services = Services()
        self.old = b'synthetic-previous-runtime'
        self.new = b'synthetic-new-runtime'
        self.canonical = self.app / activation.CANONICAL
        self.artifact = self.app / 'aegis-agent-darwin-arm64'
        self.canonical.write_bytes(self.old)
        self.canonical.chmod(0o755)
        self.artifact.write_bytes(self.new)
        self.artifact.chmod(0o755)
        self.manifest = self.app / 'aegis-runtime-manifest.json'
        self.manifest.write_text(json.dumps({'schema': 'aegis.macos-runtime/v1', 'agent_version': '1.2.3',
                                            'files': {self.artifact.name: activation.digest(self.new)}}))

    def change(self, mode='stage'):
        return activation.change(self.app, self.services, mode, '1.2.3', 'arm64', self.owner)

    def journal(self):
        return json.loads((self.app / activation.JOURNAL).read_text())

    def test_stage_retains_old_inode_and_private_backup_then_confirms_without_claiming_health(self):
        with self.canonical.open('rb') as old_open:
            self.assertEqual(self.change(), 'staged')
            self.assertEqual(old_open.read(), self.old)
        self.assertEqual(self.canonical.read_bytes(), self.new)
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), self.old)
        self.assertEqual((self.app / activation.BACKUP).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.canonical.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.services.stops, [('system', 'com.aegis.agent'), ('system', 'com.company.aegis-agent')])
        with self.assertRaisesRegex(activation.ActivationError, 'registration_unconfirmed'):
            self.change('confirm')
        self.assertEqual(self.journal()['status'], 'staged')
        self.services.registered = True
        self.assertEqual(self.change('confirm'), 'service_registered')

    def test_failed_stop_retains_old_and_checkpoint_and_can_resume(self):
        self.services.fail_stop = True
        with self.assertRaises(maintenance.MaintenanceError):
            self.change()
        self.assertEqual(self.canonical.read_bytes(), self.old)
        self.assertEqual(self.journal()['status'], 'preparing')
        self.services.fail_stop = False
        self.assertEqual(self.change(), 'staged')

    def test_repeated_stage_preserves_original_backup(self):
        self.change()
        self.change()
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), self.old)
        self.assertEqual(self.journal()['previous_sha256'], activation.digest(self.old))

    def test_reinstall_completed_identical_candidate_does_not_replace_original_backup(self):
        self.change()
        self.services.registered = True
        self.change('confirm')
        self.change()
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), self.old)
        self.assertEqual(self.journal()['previous_sha256'], activation.digest(self.old))

    def test_journal_symlink_never_follows_external_state(self):
        outside = self.app / 'external-record'
        outside.write_bytes(b'unchanged')
        (self.app / activation.JOURNAL).symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            self.change()
        self.assertEqual(outside.read_bytes(), b'unchanged')
        self.assertEqual(self.services.stops, [])

    def test_restore_after_checkpoint_interruption_can_resume(self):
        self.change()
        original = activation.save
        def interrupted(parent, journal):
            if journal['status'] == 'restored_activation_pending':
                raise OSError('synthetic interruption')
            original(parent, journal)
        with patch.object(activation, 'save', side_effect=interrupted), self.assertRaises(OSError):
            self.change('restore')
        self.assertEqual(self.canonical.read_bytes(), self.old)
        self.assertEqual(self.journal()['status'], 'restoring')
        self.assertEqual(self.change('restore'), 'restored_activation_pending')

    def test_crash_after_replacement_resumes_exact_candidate(self):
        original = activation.save
        def interrupted(parent, journal):
            if journal['status'] == 'staged':
                raise OSError('synthetic checkpoint interruption')
            original(parent, journal)
        with patch.object(activation, 'save', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.change()
        self.assertEqual(self.canonical.read_bytes(), self.new)
        self.assertEqual(self.journal()['status'], 'preparing')
        self.assertEqual(self.change(), 'staged')
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), self.old)

    def test_restore_retains_backup_and_requires_separate_activation(self):
        self.change()
        self.assertEqual(self.change('restore'), 'restored_activation_pending')
        self.assertEqual(self.canonical.read_bytes(), self.old)
        self.assertFalse(self.services.registered)
        self.assertEqual(self.change('restore'), 'restored_activation_pending')
        with self.assertRaises(activation.ActivationError):
            self.change('confirm')

    def test_empty_broken_canonical_can_be_repaired_without_executing_it(self):
        self.canonical.write_bytes(b'')
        self.assertEqual(self.change(), 'staged')
        self.assertEqual(self.canonical.read_bytes(), self.new)
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), b'')
        self.assertEqual(self.journal()['previous_sha256'], activation.digest(b''))
        self.assertEqual(self.change('restore'), 'restored_activation_pending')
        self.assertEqual(self.canonical.read_bytes(), b'')
        self.assertFalse(self.services.registered)

    def test_fresh_install_has_no_invented_prior_runtime(self):
        self.canonical.unlink()
        self.change()
        self.assertIsNone(self.journal()['previous_sha256'])
        with self.assertRaisesRegex(activation.ActivationError, 'previous_runtime_unavailable'):
            self.change('restore')

    def test_tampered_backup_is_not_restored(self):
        self.change()
        (self.app / activation.BACKUP).write_bytes(b'tampered')
        with self.assertRaisesRegex(activation.ActivationError, 'integrity_failed'):
            self.change('restore')
        self.assertEqual(self.canonical.read_bytes(), self.new)

    def test_concurrent_change_while_stopping_is_not_overwritten(self):
        self.services.on_stop = lambda: self.canonical.write_bytes(b'synthetic-concurrent-update')
        with self.assertRaisesRegex(activation.ActivationError, 'runtime_changed'):
            self.change()
        self.assertEqual(self.canonical.read_bytes(), b'synthetic-concurrent-update')

    def test_pending_different_candidate_requires_recovery(self):
        self.change()
        self.artifact.write_bytes(b'another-candidate')
        value = json.loads(self.manifest.read_text())
        value['files'][self.artifact.name] = activation.digest(self.artifact.read_bytes())
        self.manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(activation.ActivationError, 'pending_activation'):
            self.change()
        self.assertEqual((self.app / activation.BACKUP).read_bytes(), self.old)

    def test_cleanup_marker_before_or_during_stop_refuses_replacement(self):
        marker = self.app / 'watch-cleanup-pending.json'
        marker.symlink_to(self.app / 'missing')
        with self.assertRaisesRegex(activation.ActivationError, 'cleanup'):
            self.change()
        self.assertEqual(self.services.stops, [])
        marker.unlink()
        self.services.on_stop = lambda: marker.write_bytes(b'pending')
        with self.assertRaisesRegex(activation.ActivationError, 'cleanup'):
            self.change()
        self.assertEqual(self.canonical.read_bytes(), self.old)

    def test_candidate_hash_mismatch_fails_before_service_mutation(self):
        self.artifact.write_bytes(b'tampered')
        with self.assertRaisesRegex(activation.ActivationError, 'candidate_integrity'):
            self.change()
        self.assertEqual(self.services.stops, [])

    def test_unsafe_canonical_or_candidate_refused_before_service_mutation(self):
        for path in (self.canonical, self.artifact):
            saved = path.read_bytes()
            for kind in ('symlink', 'hardlink', 'fifo', 'writable'):
                with self.subTest(path=path.name, kind=kind):
                    path.unlink()
                    outside = self.app / 'outside'
                    outside.write_bytes(saved)
                    if kind == 'symlink': path.symlink_to(outside)
                    elif kind == 'hardlink': os.link(outside, path)
                    elif kind == 'fifo': os.mkfifo(path)
                    else:
                        path.write_bytes(saved)
                        path.chmod(0o666)
                    with self.assertRaises((OSError, activation.ActivationError)):
                        self.change()
                    self.assertEqual(outside.read_bytes(), saved)
                    self.assertEqual(self.services.stops, [])
                    path.unlink()
                    outside.unlink()
                    path.write_bytes(saved)
                    path.chmod(0o755)

    def test_private_lock_is_exclusive(self):
        lock = os.open(self.app / '.native-runtime-activation.lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(activation.ActivationError, 'busy'):
                self.change()
        finally:
            os.close(lock)
        self.assertEqual(self.services.stops, [])

    def test_unknown_or_unreadable_journal_is_not_treated_as_fresh_install(self):
        path = self.app / activation.JOURNAL
        path.write_text('{"schema":"unknown"}')
        path.chmod(0o600)
        with self.assertRaisesRegex(activation.ActivationError, 'journal_invalid'):
            self.change()
        self.assertEqual(self.services.stops, [])

    def test_diagnostics_fail_closed_for_pending_journal(self):
        self.change()
        result = diagnostics.collect(self.app, '1.2.3', lambda value: value, self.owner,
                                     probe=lambda root: (True, True), legacy_probe=lambda: False)
        self.assertFalse(result['AegisLaunchDaemonHealthy'])
        self.assertIn('native_activation_requires_verification', result['AegisDiagnosticIssues'])
        self.services.registered = True
        self.change('confirm')
        result = diagnostics.collect(self.app, '1.2.3', lambda value: value, self.owner,
                                     probe=lambda root: (True, True), legacy_probe=lambda: False)
        self.assertNotIn('native_activation_requires_verification', result['AegisDiagnosticIssues'])
        self.assertFalse(result['AegisReportingHealthy'])

    def test_legacy_service_reappearance_prevents_confirmation(self):
        self.change()
        self.services.registered = True
        self.services.legacy = 0
        with self.assertRaisesRegex(activation.ActivationError, 'legacy_service'):
            self.change('confirm')
        self.assertEqual(self.journal()['status'], 'staged')

    def test_public_entry_refuses_relocated_runtime_before_service_access(self):
        with patch.object(activation, 'change') as change, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(activation.main(self.app, 'stage', '1.2.3'), 1)
        change.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['status'], 'system_installation_required')

    def test_service_timeout_returns_fixed_status_without_path_or_traceback(self):
        with patch.object(activation, 'APP', self.app), patch.object(activation.os, 'geteuid', return_value=0), patch.object(activation.sys, 'platform', 'darwin'), patch.object(activation, 'change', side_effect=subprocess.TimeoutExpired('synthetic-private-command', 15)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(activation.main(self.app, 'stage', '1.2.3'), 1)
        self.assertEqual(json.loads(output.getvalue()), {'schema': 'aegis.runtime-activation-result/v1', 'health_verified': False, 'status': 'activation_state_requires_verification'})

    def test_exclusive_dispatch_rejects_extra_arguments_before_any_operation(self):
        for args in (['--stage-native-runtime', '/tmp'], ['--confirm-native-runtime=anything'], ['--restore-native-runtime', '--selftest']):
            result = subprocess.run([sys.executable, str(ROOT / 'public/downloads/aegis_agent.py'), *args],
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('AEGIS_FROZEN_AGENT'), 'requires frozen candidate')
    def test_frozen_capability_without_external_interpreter_or_host_access(self):
        binary = str(Path(os.environ['AEGIS_FROZEN_AGENT']).resolve())
        # Capability path is memory-only. Deny production files, network and
        # child execution; the already-built onefile executable may unpack itself.
        profile = '(version 1)(allow default)(deny network*)(deny file-read* (subpath "/Library/Application Support/AegisAgent"))(deny process-exec (literal "/bin/launchctl") (literal "/usr/bin/python3"))'
        result = subprocess.run(['/usr/bin/sandbox-exec', '-p', profile, binary, '--runtime-activation-selftest'],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'aegis-runtime-activation-selftest-ok', result.stdout)


if __name__ == '__main__':
    unittest.main()
