"""Native rename and private journal fixtures; no host services or user files."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DL=Path(__file__).resolve().parents[1]/'public/downloads'
sys.path.insert(0,str(DL))
import aegis_macos_service_migration as m


class Services:
    def __init__(self): self.calls=[]; self.fail=False; self.system=113
    def run(self, args): self.calls.append(args); return self.system
    def stop(self, domain, label):
        self.calls.append(['stop',domain,label])
        if self.fail: raise m.MaintenanceError('service_stop_failed')


@unittest.skipUnless(sys.platform=='darwin','native Darwin exclusive rename')
class ServiceMigrationTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='aegis-service-migration-fixture-')
        self.addCleanup(self.work.cleanup)
        self.root=Path(self.work.name).resolve();self.app=self.root/'app';self.app.mkdir()
        self.home=self.root/'synthetic-home';self.launch=self.home/'Library/LaunchAgents';self.launch.mkdir(parents=True)
        self.plist=self.launch/(m.AGENT_LABELS[0]+'.plist');self.plist.write_bytes(b'synthetic launch configuration retained')
        self.backup=self.launch/(self.plist.name+m.SUFFIX)
        self.services=Services();self.owner=os.geteuid()

    def change(self, restore=False): return m.change(self.app,[self.home],self.services,restore,self.owner)
    def journal(self): return json.loads((self.app/m.JOURNAL).read_text())

    def test_prepare_is_reversible_and_keeps_runtime_and_baselines(self):
        runtime=self.home/'Library/Application Support/AegisAgent';runtime.mkdir(parents=True)
        credential=runtime/'reporting.json';credential.write_bytes(b'synthetic private config');credential.chmod(0o600)
        baseline=self.home/'AGENTS.md';baseline.write_bytes(b'synthetic personal rules')
        self.assertEqual(self.change(),{'status':'prepared','items':1})
        self.assertFalse(self.plist.exists());self.assertEqual(self.backup.read_bytes(),b'synthetic launch configuration retained')
        self.assertEqual(len(self.services.calls),2)
        self.assertEqual(self.change()['status'],'prepared')
        self.assertEqual(len(self.services.calls),4) # Repeat verifies services again.
        self.assertEqual(self.change(True)['status'],'restored_activation_pending')
        self.assertTrue(self.plist.exists());self.assertFalse(self.backup.exists())
        self.assertEqual(self.change(True)['status'],'restored_activation_pending')
        self.assertEqual(credential.read_bytes(),b'synthetic private config');self.assertEqual(baseline.read_bytes(),b'synthetic personal rules')
        self.assertEqual((self.app/m.JOURNAL).stat().st_mode & 0o777,0o600)
        self.assertNotIn(str(self.home),(self.app/m.JOURNAL).read_text())
        self.assertNotIn('bootstrap',[call[0] for call in self.services.calls])

    def test_no_legacy_files_does_not_leave_migration_journal(self):
        self.plist.unlink()
        self.assertEqual(self.change(),{'status':'no_legacy_services','items':0})
        self.assertFalse((self.app/m.JOURNAL).exists());self.assertEqual(self.services.calls,[])

    def test_stop_failure_preserves_files_and_allows_explicit_file_recovery(self):
        self.services.fail=True
        with self.assertRaisesRegex(m.MaintenanceError,'service_stop_failed'): self.change()
        self.assertTrue(self.plist.exists());self.assertFalse(self.backup.exists())
        self.assertEqual(self.journal()['status'],'preparing')
        with self.assertRaisesRegex(m.MigrationError,'recovery_required'): self.change()
        self.assertEqual(self.change(True)['status'],'restored_activation_pending')

    def test_partial_move_has_checkpoint_and_recovery_restores_recorded_move(self):
        second=self.launch/(m.AGENT_LABELS[1]+'.plist');second.write_bytes(b'synthetic second')
        rename=m.exclusive_rename;calls=[]
        def fail_second(*args):
            calls.append(args)
            if len(calls)==2: raise m.MigrationError('legacy_rename_failed')
            rename(*args)
        with patch.object(m,'exclusive_rename',side_effect=fail_second):
            with self.assertRaises(m.MigrationError): self.change()
        self.assertEqual([i['stage'] for i in self.journal()['items']],['retired','planned'])
        self.assertEqual(self.change(True)['status'],'restored_activation_pending')
        self.assertTrue(self.plist.exists());self.assertTrue(second.exists())

    def test_journal_failure_after_rename_does_not_guess_unrecorded_state(self):
        save=m.save;count=[]
        def fail_save(*args):
            count.append(1)
            if len(count)==2: raise OSError('synthetic write failure')
            save(*args)
        with patch.object(m,'save',side_effect=fail_save):
            with self.assertRaises(OSError): self.change()
        self.assertTrue(self.backup.exists());self.assertFalse(self.plist.exists())
        with self.assertRaisesRegex(m.MigrationError,'legacy_plist_changed'): self.change(True)

    def test_existing_backup_never_overwritten(self):
        self.backup.write_bytes(b'synthetic retained backup')
        with self.assertRaisesRegex(m.MigrationError,'untracked_legacy_backup'): self.change()
        self.assertEqual(self.services.calls,[])
        self.assertEqual(self.backup.read_bytes(),b'synthetic retained backup')

    def test_backup_created_during_stop_is_not_overwritten_by_rename(self):
        def stop(*args): self.backup.write_bytes(b'synthetic concurrent backup')
        self.services.stop=stop
        with self.assertRaisesRegex(m.MigrationError,'legacy_rename_failed'): self.change()
        self.assertTrue(self.plist.exists());self.assertEqual(self.backup.read_bytes(),b'synthetic concurrent backup')

    def test_changed_plist_during_stop_refuses_move(self):
        self.services.stop=lambda *args:self.plist.write_bytes(b'synthetic concurrent change')
        with self.assertRaisesRegex(m.MigrationError,'legacy_plist_changed'): self.change()
        self.assertFalse(self.backup.exists());self.assertEqual(self.plist.read_bytes(),b'synthetic concurrent change')

    def test_restore_refuses_running_system_or_modified_backup(self):
        self.change();self.services.system=0
        with self.assertRaisesRegex(m.MigrationError,'system_service_must_be_absent'): self.change(True)
        self.services.system=113;self.backup.write_bytes(b'synthetic modified backup')
        with self.assertRaisesRegex(m.MigrationError,'legacy_plist_changed'): self.change(True)
        self.assertFalse(self.plist.exists())

    def test_unsafe_source_files_fail_before_services(self):
        original=self.root/'original';original.write_bytes(b'synthetic untouched')
        self.plist.unlink()
        for kind in ('symlink','hardlink','fifo','mode','acl'):
            if kind=='symlink': self.plist.symlink_to(original)
            elif kind=='hardlink': os.link(original,self.plist)
            elif kind=='fifo': os.mkfifo(self.plist)
            else:
                self.plist.write_bytes(b'synthetic')
                if kind=='mode': self.plist.chmod(0o666)
                else: subprocess.run(['/bin/chmod','+a','everyone allow read',str(self.plist)],check=True,capture_output=True)
            with self.subTest(kind=kind), self.assertRaises((OSError,ValueError)): self.change()
            self.plist.unlink()
        self.assertEqual(self.services.calls,[]);self.assertEqual(original.read_bytes(),b'synthetic untouched')

    def test_pending_cleanup_and_invalid_journal_refuse_service_changes(self):
        marker=self.home/'Library/Application Support/AegisAgent/watch-cleanup-pending.json';marker.parent.mkdir(parents=True);marker.write_bytes(b'pending')
        with self.assertRaisesRegex(m.MigrationError,'watch_cleanup'):self.change()
        marker.unlink()
        journal=self.app/m.JOURNAL;journal.write_text('{}');journal.chmod(0o600)
        with self.assertRaisesRegex(m.MigrationError,'recovery_required'):self.change()
        self.assertEqual(self.services.calls,[])

    def test_checkpoint_refuses_new_untracked_user_service(self):
        self.change();(self.launch/(m.AGENT_LABELS[1]+'.plist')).write_bytes(b'synthetic new service')
        with self.assertRaisesRegex(m.MigrationError,'untracked_legacy_service'):self.change()

    def test_private_journal_and_lock_cannot_be_redirected_or_contended(self):
        journal=self.app/m.JOURNAL
        outside=self.root/'unmanaged';outside.write_bytes(b'synthetic untouched')
        journal.symlink_to(outside)
        with self.assertRaises(OSError): self.change()
        journal.unlink()
        lock=self.app/'.legacy-service-migration.lock'
        with lock.open('r+b') as stream:
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.MigrationError,'migration_busy'):self.change()
        self.assertEqual(self.services.calls,[]);self.assertEqual(outside.read_bytes(),b'synthetic untouched')

    def test_cleanup_marker_created_during_stop_blocks_all_moves(self):
        marker=self.home/'Library/Application Support/AegisAgent/watch-cleanup-pending.json';marker.parent.mkdir(parents=True)
        self.services.stop=lambda *args:marker.write_bytes(b'synthetic unconfirmed cleanup')
        with self.assertRaisesRegex(m.MigrationError,'watch_cleanup'):self.change()
        self.assertTrue(self.plist.exists());self.assertFalse(self.backup.exists())

    @unittest.skipUnless(os.geteuid()==0 and os.environ.get('AEGIS_FROZEN_AGENT'),'root CI with explicit frozen binary')
    def test_frozen_mode_refuses_inaccessible_home_inventory_without_external_runtime(self):
        binary=self.app/'aegis-agent';shutil.copy2(os.environ['AEGIS_FROZEN_AGENT'],binary);binary.chmod(0o755)
        profile='(version 1)(allow default)(deny network*)(deny file-read* (subpath "/Users"))(deny process-exec (require-not (literal (param "BINARY"))))'
        env={**os.environ,'PATH':'/nonexistent','PYTHONHOME':'/nonexistent','PYTHONPATH':'/nonexistent'}
        command=['/usr/bin/sandbox-exec','-D','BINARY='+str(binary),'-p',profile,str(binary)]
        for flag in ('--service-migration-selftest','--prepare-legacy-services','--restore-legacy-services'):
            r=subprocess.run(command+[flag],env=env,capture_output=True,text=True,timeout=30)
            if flag.endswith('selftest'): self.assertEqual(r.returncode,0,r.stderr)
            else:
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(json.loads(r.stdout)['status'],'migration_state_requires_verification')
        self.assertFalse((self.app/m.JOURNAL).exists())


class MigrationDispatchTests(unittest.TestCase):
    def test_nonadministrator_does_not_inventory_homes(self):
        with patch.object(os,'geteuid',return_value=501), patch.object(os,'scandir') as scan, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(Path('/synthetic')),1)
            self.assertEqual(json.loads(output.getvalue())['status'],'administrator_required');scan.assert_not_called()

    def test_mixed_or_duplicate_modes_cannot_reach_migration(self):
        spec=importlib.util.spec_from_file_location('service_migration_agent_fixture',DL/'aegis_agent.py');agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
        with patch.object(sys,'platform','darwin'),patch.object(m,'main') as main,contextlib.redirect_stderr(io.StringIO()):
            for args in (['--prepare-legacy-services','--watch'],['--restore-legacy-services','--restore-legacy-services'],['--prepare-legacy-services=x']):
                with patch.object(sys,'argv',['aegis-agent']+args):self.assertEqual(agent.main(),2)
            main.assert_not_called()


if __name__=='__main__': unittest.main()
