"""Public status contract; all state and health inputs are synthetic."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'public/downloads'))
import aegis_macos_desktop_status as desktop


class DesktopStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name).resolve() / 'app'
        self.app.mkdir(mode=0o755)
        self.target = self.app / desktop.NAME
        self.health = {source: True for source in desktop.CHECKS.values()}
        self.health['AegisPolicyVersion'] = '1.2.3'
        self.value = desktop.snapshot(self.health, '0.37.3', 1800000000)

    def publish(self):
        desktop.publish(self.app, self.value, owner=os.getuid())

    def test_allowlist_never_exports_private_or_unrecognized_values(self):
        self.health.update(deviceId='synthetic-device', findings=['synthetic-content'], secret='synthetic-secret')
        value = desktop.snapshot(self.health, '0.37.3', 1800000000)
        self.assertEqual(value, self.value)
        self.assertNotIn('synthetic', json.dumps(value))
        for flag in [1, 'true', {}, None, []]:
            self.assertFalse(desktop.snapshot({'AegisInstalled': flag}, '1.0.0', 1)['checks']['installed'])
        self.assertEqual(desktop.snapshot({}, '1.0.0', 1)['policy_version'], 'unknown')

    def test_contract_rejects_invalid_versions_timestamps_and_additions(self):
        for version in ['1.2.3\n', '<1.2.3>', '1'*65+'.2.3', None]:
            with self.assertRaises(ValueError):
                desktop.snapshot({}, version, 1)
        for timestamp in [True, 1.5, -1, 253402300800]:
            with self.assertRaises(ValueError):
                desktop.snapshot({}, '1.2.3', timestamp)
        for delta in [{'raw_report': {}}, {'schema': 'unknown'}, {'checks': {'installed': True}}]:
            with self.assertRaises(ValueError):
                desktop.publish(self.app, self.value | delta, owner=os.getuid())
        self.assertFalse(self.target.exists())

    def test_atomic_publication_preserves_old_open_snapshot(self):
        self.publish()
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o644)
        with self.target.open() as old:
            self.value['checks']['service'] = False
            self.publish()
            self.assertTrue(json.load(old)['checks']['service'])
        self.assertFalse(json.loads(self.target.read_text())['checks']['service'])
        self.assertEqual(list(self.app.iterdir()), [self.target])

    def test_failed_replace_preserves_snapshot_and_cleans_temporary_file(self):
        self.publish()
        before = self.target.read_bytes()
        with patch.object(desktop.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(list(self.app.iterdir()), [self.target])

    def test_directory_and_file_must_be_owned_and_not_writable_by_others(self):
        with self.assertRaises(ValueError):
            desktop.publish(self.app, self.value, owner=os.getuid()+1)
        self.app.chmod(0o777)
        with self.assertRaises(ValueError):
            self.publish()
        self.app.chmod(0o755)
        self.publish()
        self.target.chmod(0o666)
        with self.assertRaises(ValueError):
            self.publish()

    def test_rejects_symlink_hardlink_fifo_and_symlink_parent(self):
        outside = self.app.parent / 'outside'
        outside.write_text('synthetic preserved data')
        self.target.symlink_to(outside)
        with self.assertRaises(OSError):
            self.publish()
        self.target.unlink()
        os.link(outside, self.target)
        with self.assertRaises(ValueError):
            self.publish()
        self.target.unlink()
        os.mkfifo(self.target)
        with self.assertRaises(ValueError):
            self.publish()
        self.target.unlink()
        alias = self.app.parent / 'alias'
        alias.symlink_to(self.app)
        with self.assertRaises(OSError):
            desktop.publish(alias, self.value, owner=os.getuid())
        self.assertEqual(outside.read_text(), 'synthetic preserved data')

    def test_acl_failure_prevents_publication(self):
        with patch.object(desktop, 'require_no_acl', side_effect=ValueError('acl')):
            with self.assertRaises(ValueError):
                self.publish()
        self.assertFalse(self.target.exists())

    def test_development_and_unprivileged_watch_never_collect(self):
        for platform, owner, frozen, executable, app in [
            ('linux', 0, True, str(desktop.APP/'aegis-agent'), desktop.APP),
            ('darwin', 501, True, str(desktop.APP/'aegis-agent'), desktop.APP),
            ('darwin', 0, False, str(desktop.APP/'aegis-agent'), desktop.APP),
            ('darwin', 0, True, '/synthetic/agent', desktop.APP),
            ('darwin', 0, True, str(desktop.APP/'aegis-agent'), self.app),
        ]:
            with patch.object(desktop.sys, 'platform', platform), patch.object(desktop.os, 'geteuid', return_value=owner), \
                 patch.object(desktop.sys, 'frozen', frozen, create=True), patch.object(desktop.sys, 'executable', executable), \
                 patch('aegis_macos_diagnostics.collect') as collect:
                with desktop.watch(app, '1.2.3', None):
                    pass
                collect.assert_not_called()

    def test_worker_does_not_hold_watchdog_shutdown_when_diagnostics_stall(self):
        entered, release = threading.Event(), threading.Event()
        def slow(*args):
            entered.set()
            release.wait(5)
            return self.health
        try:
            with patch.object(desktop.sys, 'platform', 'darwin'), patch.object(desktop.os, 'geteuid', return_value=0), \
                 patch.object(desktop.sys, 'frozen', True, create=True), \
                 patch.object(desktop.sys, 'executable', str(desktop.APP/'aegis-agent')), \
                 patch('aegis_macos_diagnostics.collect', side_effect=slow), patch.object(desktop, 'publish') as publish:
                with desktop.watch(desktop.APP, '1.2.3', None):
                    self.assertTrue(entered.wait(2))
                    start = time.monotonic()
                self.assertLess(time.monotonic()-start, 1)
                release.set()
                for worker in threading.enumerate():
                    if worker.name == 'aegis-desktop-status':
                        worker.join(2)
                publish.assert_not_called()
        finally:
            release.set()


if __name__ == '__main__':
    unittest.main()
