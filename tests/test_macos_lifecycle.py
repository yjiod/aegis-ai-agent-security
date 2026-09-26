"""Shared lease and persistent intent tests using synthetic files only."""
import contextlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'public/downloads'))
import aegis_macos_lifecycle as lifecycle
import aegis_macos_runtime_activation as activation
import aegis_macos_maintenance as maintenance
import aegis_self_update as updater
import aegis_macos_diagnostics as diagnostics


class MacLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.app = self.root / 'app'
        self.app.mkdir()
        self.owner = os.geteuid()

    def lease(self, mode):
        return lifecycle.lease(self.app, mode, self.owner)

    def state(self):
        return lifecycle.state(self.app, self.owner)

    def save_state(self, status):
        with maintenance.directory(self.root) as fd:
            lifecycle.save(fd, status)

    def ready_journal(self, status='service_registered'):
        journal = {'schema': activation.SCHEMA, 'status': status, 'previous_sha256': None,
                   'target_sha256': 'a' * 64, 'target_version': '1.2.3'}
        path = self.app / activation.JOURNAL
        path.write_text(json.dumps(journal))
        path.chmod(0o600)

    def test_all_mutators_contend_for_one_lock_before_work(self):
        with self.lease('update'):
            for operation in ('stage', 'confirm', 'restore', 'uninstall', 'update'):
                with self.subTest(operation=operation), self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_busy'):
                    with self.lease(operation):
                        self.fail('overlapping lease entered')
        self.assertIsNone(self.state())

    def test_lock_survives_runtime_directory_move_and_recreation(self):
        with self.lease('uninstall'):
            self.app.rename(self.root / 'archived')
            self.app.mkdir()
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_busy'):
                with self.lease('stage'):
                    self.fail('new directory bypassed live lock')
        self.assertEqual(self.state(), 'uninstalled')
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_pending'):
            with self.lease('update'):
                self.fail('uninstalled state allowed update')

    def test_independent_process_holds_same_lease(self):
        script = "import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); from aegis_macos_lifecycle import lease;\nwith lease(Path(sys.argv[2]),'update',int(sys.argv[3])):\n print('held',flush=True); sys.stdin.readline()\n"
        child = subprocess.Popen([sys.executable, '-c', script, str(ROOT / 'public/downloads'), str(self.app), str(self.owner)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'lease process did not start')
            self.assertEqual(child.stdout.readline().strip(), 'held')
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_busy'):
                with self.lease('stage'):
                    self.fail('second process bypassed lease')
            child.communicate('\n', timeout=10)
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=10)
        with self.lease('update'):
            self.assertIsNone(self.state())

    def test_pending_states_deny_update_before_fetch_or_staging(self):
        for status in ('installing', 'recovery_pending', 'uninstalling', 'uninstalled'):
            self.save_state(status)
            with self.subTest(status=status), patch.object(updater, '_maintenance_context', return_value=self.lease('update')), patch.object(updater, 'fetch_manifest') as fetch:
                result = updater.check_and_apply('https://aegis.example.test/manifest', '1.2.3', 'synthetic', 'native', str(self.app / 'aegis-agent'))
                self.assertEqual(result, {'updated': False, 'reason': 'maintenance_pending'})
                fetch.assert_not_called()
                self.assertFalse((self.app / 'aegis-agent.staging').exists())

    def test_uninstall_failure_retains_intent_and_blocks_new_activation(self):
        with self.assertRaises(OSError):
            with self.lease('uninstall'):
                raise OSError('synthetic failure')
        self.assertEqual(self.state(), 'uninstalling')
        for mode in ('stage', 'confirm', 'restore'):
            with self.subTest(mode=mode), self.assertRaisesRegex(lifecycle.LifecycleError, 'uninstall_recovery_required'):
                with self.lease(mode):
                    self.fail('incomplete uninstall bypassed')
        with self.lease('uninstall'):
            self.assertEqual(self.state(), 'uninstalling')
        self.assertEqual(self.state(), 'uninstalled')
        with self.lease('stage'):
            self.assertEqual(self.state(), 'installing')

    def test_successful_confirmation_reopens_updates_only_with_completed_journal(self):
        self.ready_journal('staged')
        with self.lease('stage'):
            self.assertEqual(self.state(), 'installing')
        with self.assertRaises(RuntimeError):
            with self.lease('confirm'):
                raise RuntimeError('synthetic registration failure')
        self.assertEqual(self.state(), 'installing')
        self.ready_journal()
        with self.lease('confirm'):
            self.assertEqual(self.state(), 'installing')
        self.assertEqual(self.state(), 'ready')
        with self.lease('update'):
            self.assertEqual(self.state(), 'ready')
        with self.lease('restore'):
            self.assertEqual(self.state(), 'recovery_pending')

    def test_missing_shared_state_does_not_ignore_older_pending_activation_journal(self):
        self.ready_journal('staged')
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'activation_pending'):
            with self.lease('update'):
                self.fail('old pending journal bypassed')
        self.assertIsNone(self.state())

    def test_absent_runtime_does_not_recreate_it_or_fetch(self):
        self.app.rmdir()
        with patch.object(updater, '_maintenance_context', return_value=self.lease('update')), patch.object(updater, 'fetch_manifest') as fetch:
            result = updater.check_and_apply('https://aegis.example.test/manifest', '1.2.3', 'synthetic', 'native', str(self.app / 'aegis-agent'))
        self.assertFalse(result['updated'])
        self.assertTrue(result['reason'].startswith('maintenance_unavailable:'))
        fetch.assert_not_called()
        self.assertFalse(self.app.exists())

    def test_pending_or_invalid_external_state_prevents_healthy_diagnostics(self):
        self.save_state('uninstalling')
        value = diagnostics.collect(self.app, '1.2.3', lambda value: value, self.owner,
                                    probe=lambda root: (True, True), legacy_probe=lambda: False)
        self.assertFalse(value['AegisLaunchDaemonHealthy'])
        self.assertIn('system_maintenance_pending', value['AegisDiagnosticIssues'])
        (self.root / lifecycle.STATE).write_text('{"schema":"unknown"}')
        value = diagnostics.collect(self.app, '1.2.3', lambda value: value, self.owner,
                                    probe=lambda root: (True, True), legacy_probe=lambda: False)
        self.assertFalse(value['AegisLaunchDaemonHealthy'])
        self.assertIn('system_maintenance_state_unavailable', value['AegisDiagnosticIssues'])

    def test_cleanup_marker_blocks_update(self):
        (self.app / 'watch-cleanup-pending.json').symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'watch_cleanup'):
            with self.lease('update'):
                self.fail('cleanup marker ignored')

    def test_lock_and_state_reject_links_and_nonprivate_files(self):
        for name in (lifecycle.LOCK, lifecycle.STATE):
            path = self.root / name
            outside = self.root / 'untouched'
            outside.write_bytes(b'unchanged')
            for kind in ('symlink', 'hardlink', 'writable', 'fifo'):
                with self.subTest(name=name, kind=kind):
                    if path.exists() or path.is_symlink(): path.unlink()
                    if kind == 'symlink': path.symlink_to(outside)
                    elif kind == 'hardlink': os.link(outside, path)
                    elif kind == 'fifo': os.mkfifo(path)
                    else:
                        path.write_bytes(b'{}')
                        path.chmod(0o666)
                    with self.assertRaises((OSError, ValueError, maintenance.MaintenanceError)):
                        with self.lease('stage'):
                            self.fail('unsafe state accepted')
                    self.assertEqual(outside.read_bytes(), b'unchanged')
                    path.unlink()
            outside.unlink()

    def test_receipt_callback_runs_before_lease_release(self):
        def callback(result):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_busy'):
                with self.lease('uninstall'):
                    self.fail('receipt write not serialized')
            self.assertTrue(result['updated'])
        with patch.object(updater, '_maintenance_context', return_value=self.lease('update')), patch.object(updater, '_check_and_apply', return_value={'updated': True, 'reason': 'ok'}):
            result = updater.check_and_apply('', '', '', '', str(self.app / 'aegis-agent'), on_applied=callback)
        self.assertEqual(result, {'updated': True, 'reason': 'ok'})

    def test_receipt_failure_does_not_misreport_applied_bytes_as_rolled_back(self):
        def callback(result):
            raise OSError('synthetic write failure')
        with patch.object(updater, '_maintenance_context', return_value=self.lease('update')), patch.object(updater, '_check_and_apply', return_value={'updated': True, 'reason': 'ok'}):
            result = updater.check_and_apply('', '', '', '', str(self.app / 'aegis-agent'), on_applied=callback)
        self.assertTrue(result['updated'])
        self.assertEqual(result['receipt_status'], 'updated_receipt_unavailable')

    def test_uninstall_cannot_stop_services_while_update_holds_lease(self):
        class Services:
            def stop(self, *args):
                raise AssertionError('service stop reached during concurrent update')
        with self.lease('update'), self.assertRaisesRegex(lifecycle.LifecycleError, 'maintenance_busy'):
            maintenance.uninstall(self.app, self.root / 'daemons', [], self.root, Services())
        self.assertTrue(self.app.is_dir())

    def test_system_target_dispatch_uses_guard_and_rejects_architecture_artifact(self):
        with patch.object(updater.sys, 'platform', 'darwin'), patch.object(lifecycle, 'lease', return_value=contextlib.nullcontext()) as guard:
            with updater._maintenance_context(str(lifecycle.APP / 'aegis-agent')):
                guard.assert_called_once_with(lifecycle.APP, 'update')
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'unsupported_system_update_target'):
                updater._maintenance_context(str(lifecycle.APP / 'aegis-agent-darwin-arm64'))


if __name__ == '__main__':
    unittest.main()
