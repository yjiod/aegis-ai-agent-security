"""Synthetic current-user retirement; never alter actual launchd or user state."""
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
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DL = ROOT / 'public/downloads'
sys.path.insert(0, str(DL))
import aegis_macos_user_retirement as m


class Services:
    def __init__(self): self.calls = []; self.fail = False; self.after_stop = None; self.reappeared = False
    def stop(self, domain, label):
        self.calls.append((domain, label))
        if self.fail: raise m.MaintenanceError('service_stop_failed')
        if self.after_stop: self.after_stop()
    def run(self, args):
        return 0 if args[1].count('/') == 1 or self.reappeared else 113


@unittest.skipUnless(sys.platform == 'darwin', 'Darwin exclusive rename and ACLs')
class UserRetirementTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='aegis-user-retirement-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.home = self.root/'home'
        self.launch = self.home/'Library/LaunchAgents'; self.launch.mkdir(parents=True)
        self.support = self.home/'Library/Application Support'; self.support.mkdir()
        self.runtime = self.support/'AegisAgent'; self.runtime.mkdir()
        self.private = self.runtime/'reporting.json'; self.private.write_bytes(b'synthetic retained credential fixture')
        self.baseline = self.home/'AGENTS.md'; self.baseline.write_bytes(b'synthetic rules remain unchanged')
        self.plist = self.launch/'com.aegis.agent.plist'; self.plist.write_bytes(b'synthetic launch file')
        self.services = Services(); self.uid = os.geteuid()

    def retire(self): return m.retire(self.home, self.uid, self.services)
    def records(self): return list((self.support/m.ARCHIVE).glob('*/status.json'))

    def test_only_current_user_domains_and_launch_files_change(self):
        sibling = self.root/'other-user'; sibling.mkdir(); other = sibling/'untouched'; other.write_bytes(b'other user')
        private_before = (self.private.read_bytes(), self.private.stat().st_mtime_ns)
        result = self.retire()
        self.assertEqual(result, {'status':'retired_with_retained_state','archived_launch_files':1})
        self.assertEqual(self.services.calls, [(d,l) for d in (f'gui/{self.uid}',f'user/{self.uid}') for l in m.AGENT_LABELS])
        self.assertFalse(self.plist.exists())
        record = self.records()[0]; value = json.loads(record.read_text())
        self.assertEqual(value['status'], 'retired_with_retained_state')
        self.assertEqual(value['items'][0]['stage'], 'archived')
        self.assertEqual((record.parent/self.plist.name).read_bytes(), b'synthetic launch file')
        self.assertEqual(private_before, (self.private.read_bytes(), self.private.stat().st_mtime_ns))
        self.assertEqual(self.baseline.read_bytes(), b'synthetic rules remain unchanged')
        self.assertEqual(other.read_bytes(), b'other user')
        self.assertNotIn(str(self.home), record.read_text())
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)

    def test_missing_plist_still_checks_jobs_and_repeat_retains_archive(self):
        self.retire(); first = self.records()[0].read_bytes()
        self.services.calls.clear()
        self.assertEqual(self.retire()['archived_launch_files'], 0)
        self.assertEqual(len(self.services.calls), 4)
        self.assertIn(first, [p.read_bytes() for p in self.records()])

    def test_stop_failure_keeps_files_and_partial_audit(self):
        self.services.fail = True
        with self.assertRaisesRegex(m.MaintenanceError, 'service_stop_failed'): self.retire()
        self.assertTrue(self.plist.exists())
        self.assertEqual(json.loads(self.records()[0].read_text())['status'], 'partial')

    def test_initial_journal_failure_and_later_invalid_file_stop_no_services(self):
        with patch.object(m, 'save_journal', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError): self.retire()
        self.assertEqual(self.services.calls, [])
        second = self.launch/'com.company.aegis-agent.plist'
        second.write_bytes(b'synthetic unsafe file'); second.chmod(0o666)
        with self.assertRaises(ValueError): self.retire()
        self.assertEqual(self.services.calls, [])
        self.assertTrue(self.plist.exists())

    def test_pending_cleanup_before_or_after_stop_refuses_moves(self):
        marker = self.runtime/'watch-cleanup-pending.json'
        marker.write_text('synthetic')
        with self.assertRaisesRegex(m.MaintenanceError, 'watch_cleanup'): self.retire()
        self.assertEqual(self.services.calls, [])
        marker.unlink()
        self.services.after_stop = lambda: marker.write_text('synthetic')
        with self.assertRaisesRegex(m.MaintenanceError, 'watch_cleanup'): self.retire()
        self.assertTrue(self.plist.exists())

    def test_links_hardlinks_fifo_and_acl_refused_before_stop(self):
        for kind in ('symlink','hardlink','fifo','acl'):
            with self.subTest(kind=kind):
                self.plist.unlink(missing_ok=True)
                target = self.root/'target'; target.write_bytes(b'unmanaged')
                if kind == 'symlink': self.plist.symlink_to(target)
                elif kind == 'hardlink': os.link(target, self.plist)
                elif kind == 'fifo': os.mkfifo(self.plist)
                else:
                    self.plist.write_bytes(b'synthetic')
                    subprocess.run(['/bin/chmod','+a','everyone allow read',str(self.plist)],check=True,capture_output=True)
                with self.assertRaises((OSError, ValueError, m.MaintenanceError)): self.retire()
                self.assertEqual(self.services.calls, [])
                self.assertEqual(target.read_bytes(), b'unmanaged')

    def test_unsafe_archive_or_lock_never_stops_services(self):
        archive = self.support/m.ARCHIVE; archive.mkdir(mode=0o755)
        with self.assertRaisesRegex(m.MaintenanceError, 'unsafe_user_archive'): self.retire()
        archive.chmod(0o700)
        lock = archive/'.lock'; lock.symlink_to(self.private)
        with self.assertRaises(OSError): self.retire()
        self.assertEqual(self.services.calls, [])

    def test_concurrent_lock_refuses_without_service_changes(self):
        archive = self.support/m.ARCHIVE; archive.mkdir(mode=0o700)
        fd = os.open(archive/'.lock', os.O_RDWR|os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.MaintenanceError, 'user_retirement_busy'): self.retire()
        finally: os.close(fd)
        self.assertEqual(self.services.calls, [])

    def test_changed_source_or_existing_destination_is_not_overwritten(self):
        self.services.after_stop = lambda: self.plist.write_bytes(b'concurrent edit')
        with self.assertRaisesRegex(m.MaintenanceError, 'legacy_plist_changed'): self.retire()
        self.assertEqual(self.plist.read_bytes(), b'concurrent edit')
        self.services.after_stop = lambda: (max(self.records(), key=lambda p:p.stat().st_mtime_ns).parent/self.plist.name).write_bytes(b'existing archive')
        with self.assertRaises(ValueError): self.retire()
        self.assertEqual(self.plist.read_bytes(), b'concurrent edit')
        self.assertTrue(any((p.parent/self.plist.name).read_bytes()==b'existing archive' for p in self.records() if (p.parent/self.plist.name).exists()))

    def test_checkpoint_failure_after_move_keeps_archived_bytes_and_partial_state(self):
        original = m.save_journal; calls = 0
        def checkpoint(*args):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('synthetic sync failure')
            return original(*args)
        with patch.object(m, 'save_journal', side_effect=checkpoint):
            with self.assertRaises(OSError): self.retire()
        record = self.records()[0]
        self.assertEqual(json.loads(record.read_text())['status'], 'partial')
        self.assertEqual((record.parent/self.plist.name).read_bytes(), b'synthetic launch file')

    def test_recreated_file_does_not_produce_completed_claim(self):
        original = m.exclusive_rename
        def recreate(*args, **kwargs):
            original(*args, **kwargs); self.plist.write_bytes(b'new file')
        with patch.object(m, 'exclusive_rename', side_effect=recreate):
            with self.assertRaisesRegex(m.MaintenanceError, 'legacy_source_recreated'): self.retire()
        self.assertEqual(self.plist.read_bytes(), b'new file')
        self.assertEqual(json.loads(self.records()[0].read_text())['status'], 'partial')

    def test_reappeared_registration_keeps_partial_state_after_archive(self):
        self.services.reappeared = True
        with self.assertRaisesRegex(m.MaintenanceError, 'service_absence_unconfirmed'): self.retire()
        record = self.records()[0]
        self.assertEqual(json.loads(record.read_text())['status'], 'partial')
        self.assertTrue((record.parent/self.plist.name).exists())

    def test_launch_directory_disappearing_after_move_is_incomplete(self):
        original = m.exclusive_rename
        def disappear(*args, **kwargs):
            original(*args, **kwargs); self.launch.rmdir()
        with patch.object(m, 'exclusive_rename', side_effect=disappear):
            with self.assertRaisesRegex(m.MaintenanceError, 'legacy_launch_directory_disappeared'): self.retire()
        self.assertEqual(json.loads(self.records()[0].read_text())['status'], 'partial')


class UserRetirementDispatchTests(unittest.TestCase):
    def test_main_rejects_root_and_elevated_identity_before_home_lookup(self):
        for uid, euid in ((0,0),(501,0)):
            with patch.object(os,'getuid',return_value=uid), patch.object(os,'geteuid',return_value=euid), patch.object(m,'retire') as retire, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(),2); retire.assert_not_called()

    def test_main_uses_account_database_not_home_or_sudo_environment(self):
        fake = types.SimpleNamespace(getpwuid=lambda uid:types.SimpleNamespace(pw_dir='/Users/synthetic-fixture'))
        with patch.object(sys,'platform','darwin'), patch.object(os,'getuid',return_value=501), patch.object(os,'geteuid',return_value=501), patch.dict(sys.modules,{'pwd':fake}), patch.dict(os.environ,{'HOME':'/outside','SUDO_USER':'unrelated'}), patch.object(m,'retire',return_value={'status':'fixture'}) as retire, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(),0)
            self.assertEqual(retire.call_args.args[:2],(Path('/Users/synthetic-fixture'),501))

    def test_agent_modes_are_exclusive_and_do_not_scan(self):
        import aegis_agent as agent
        with patch.dict(sys.modules,{'aegis_macos_user_retirement':m}), patch.object(sys,'platform','darwin'), patch.object(m,'main',return_value=19) as main, patch.object(agent,'hardware_device_id',side_effect=AssertionError('identity lookup')):
            for args in (['--retire-legacy-user','--watch'],['--retire-legacy-user=/Users/other'],['--retire-legacy-user','--uninstall-system'],['--','--retire-legacy-user']):
                with patch.object(sys,'argv',['agent',*args]): self.assertEqual(agent.main(),2)
            main.assert_not_called()
            with patch.object(sys,'argv',['agent','--retire-legacy-user']): self.assertEqual(agent.main(),19)
            with patch.object(sys,'argv',['agent','--user-retirement-selftest']): self.assertEqual(agent.main(),0)


@unittest.skipUnless(sys.platform == 'darwin', 'Mac shell tools and sandbox')
class LegacyLauncherTests(unittest.TestCase):
    def test_retired_builder_emits_only_launcher_and_install_has_no_effects(self):
        with tempfile.TemporaryDirectory(prefix='aegis-legacy-launcher-') as temp:
            root = Path(temp).resolve(); scripts=root/'scripts';scripts.mkdir();downloads=root/'public/downloads';downloads.mkdir(parents=True)
            shutil.copy2(ROOT/'scripts/build-macos-standalone.sh',scripts/'build-macos-standalone.sh')
            shutil.copy2(DL/'retire-aegis-user-macos.sh',downloads/'retire-aegis-user-macos.sh')
            subprocess.run(['/bin/sh',str(scripts/'build-macos-standalone.sh')],check=True,capture_output=True)
            output=downloads/'aegis-agent-macos-standalone.run'
            self.assertEqual(output.read_bytes(),(downloads/'retire-aegis-user-macos.sh').read_bytes())
            for args,status in (([], 'native_package_installation_required'),(['--server','https://aegis.example.test'], 'native_package_installation_required')):
                profile='(version 1)(allow default)(deny network*)(deny file-write*)(deny process-exec (require-all (require-not (literal "/bin/sh")) (require-not (literal "/bin/bash"))))'
                result=subprocess.run(['/usr/bin/sandbox-exec','-p',profile,'/bin/sh',str(output),*args],capture_output=True,text=True)
                self.assertEqual(result.returncode,2,result.stderr);self.assertEqual(json.loads(result.stdout)['status'],status)

    def test_wrapper_checks_capability_then_delegates_current_user_only(self):
        with tempfile.TemporaryDirectory(prefix='aegis-retirement-wrapper-') as temp:
            root=Path(temp).resolve(); library=root/'Library';app=library/'Application Support/AegisAgent';app.mkdir(parents=True)
            binary=app/'aegis-agent';calls=root/'calls'
            binary.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$CALLS"\nif [ "$1" = --user-retirement-selftest ]; then exit "${SELFTEST_RC:-0}"; fi\nprintf \'{"status":"delegated"}\\n\'\n');binary.chmod(0o755)
            stat_tool=root/'stat';stat_tool.write_text('#!/bin/sh\nif [ "$2" = %u ]; then echo 0; else exec /usr/bin/stat "$@"; fi\n');stat_tool.chmod(0o755)
            source=(DL/'retire-aegis-user-macos.sh').read_text().replace('/Library',str(library)).replace('/usr/bin/stat',str(stat_tool)).replace('/usr/bin/id -u','printf 501')
            wrapper=root/'wrapper.sh';wrapper.write_text(source)
            env={**os.environ,'CALLS':str(calls),'PATH':'/nonexistent','PYTHONHOME':'/nonexistent'}
            for name in ('AEGIS_INSTALL_DIR','AEGIS_PLIST','AEGIS_LABEL'):env.pop(name,None)
            profile='(version 1)(allow default)(deny network*)(deny process-exec (regex #"/python[0-9.]*$") (literal "/bin/launchctl"))(deny file-write* (require-all (require-not (subpath (param "FIXTURE"))) (require-not (literal "/dev/null"))))'
            def run(): return subprocess.run(['/usr/bin/sandbox-exec','-D','FIXTURE='+str(root),'-p',profile,'/bin/sh',str(wrapper),'--uninstall'],capture_output=True,text=True,env=env)
            result=run();self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(calls.read_text().splitlines(),['--user-retirement-selftest','--retire-legacy-user'])
            calls.unlink();env['SELFTEST_RC']='1'
            result=run();self.assertEqual(result.returncode,1)
            self.assertEqual(json.loads(result.stdout)['status'],'native_retirement_capability_required')
            self.assertEqual(calls.read_text().splitlines(),['--user-retirement-selftest'])
            calls.unlink();env['AEGIS_LABEL']='com.other'
            self.assertEqual(json.loads(run().stdout)['status'],'custom_user_retirement_not_supported');self.assertFalse(calls.exists())
            env.pop('AEGIS_LABEL'); env.pop('SELFTEST_RC')
            subprocess.run(['/bin/chmod','+a','everyone allow read',str(binary)],check=True,capture_output=True)
            self.assertEqual(json.loads(run().stdout)['status'],'trusted_runtime_required');self.assertFalse(calls.exists())


@unittest.skipUnless(sys.platform == 'darwin' and os.getenv('AEGIS_MACOS_TEST_BINARY'), 'frozen Mac candidate required')
class FrozenUserRetirementTests(unittest.TestCase):
    def test_embedded_capability_and_denied_home_do_not_run_external_tools(self):
        work=tempfile.TemporaryDirectory(prefix='aegis-frozen-user-retirement-');self.addCleanup(work.cleanup)
        candidate=Path(work.name).resolve()/'aegis-agent'
        shutil.copy2(Path(os.environ['AEGIS_MACOS_TEST_BINARY']).resolve(),candidate)
        binary=str(candidate)
        profile='(version 1)(allow default)(deny network*)(deny file-read* (subpath "/Users"))(deny process-exec (require-not (literal (param "BINARY"))))'
        for args,expected in ((['--user-retirement-selftest'],0),(['--retire-legacy-user','--watch'],2),(['--retire-legacy-user'],1)):
            result=subprocess.run(['/usr/bin/sandbox-exec','-D','BINARY='+binary,'-p',profile,binary,*args],capture_output=True,text=True,timeout=60,env={**os.environ,'PYTHONHOME':'/nonexistent','PYTHONPATH':'/nonexistent'})
            if args==['--retire-legacy-user']:
                value=json.loads(result.stdout);self.assertIn(value['status'],('incomplete','unprivileged_macos_user_required'))
                self.assertNotEqual(result.returncode,0)
            else:self.assertEqual(result.returncode,expected,result.stderr)


if __name__ == '__main__': unittest.main()
