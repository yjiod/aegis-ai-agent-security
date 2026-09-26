"""Protected migration intent, synthetic transport, no real host state."""
import importlib.util
import contextlib
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

DL = Path(__file__).resolve().parents[1] / 'public/downloads'
sys.path.insert(0, str(DL))
import aegis_macos_configuration as config
import aegis_macos_enrollment as enrollment

DEVICE = '012345abcdef'
OLD = 'https://old.example.test/aegis/v1/reports'
NEW = 'https://new.example.test/aegis/v1/reports'


def credentials(url):
    return {'schema': 'aegis.reporting/v1', 'report_url': url,
            'report_token': 'synthetic-token-'*4, 'signing_secret': 'synthetic-signing-'*4}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='aegis-migration-fixture-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.reporting = self.root/'reporting.json'
        self.intent = self.root/'server-override.json'
        config.write_config(self.root, credentials(OLD), os.geteuid())
        self.before = self.reporting.read_bytes()
        self.policy = self.root/'aegis-policy.json'
        self.policy.write_bytes(b'synthetic policy retained')
        self.key = self.root/'ed25519-public.b64'
        self.key.write_bytes(b'synthetic pinned public key retained')
        self.network = patch.object(enrollment, 'request_config', return_value=credentials(NEW)).start()
        self.addCleanup(patch.stopall)

    def request(self, value=None):
        self.intent.write_text(json.dumps({'server_url':'https://new.example.test'} if value is None else value))
        self.intent.chmod(0o600)

    def migrate(self, **kwargs):
        return enrollment.migrate(self.root, DEVICE, '1.2.3', owner=os.geteuid(), **kwargs)

    def test_migration_changes_only_reporting_and_does_not_repeat(self):
        self.request()
        result = self.migrate()
        self.assertEqual(result['_migration_status'], 'applied')
        self.assertEqual(config.read_config(self.reporting)['report_url'], NEW)
        self.assertNotIn('_migration_status', json.loads(self.reporting.read_text()))
        self.assertIsNone(self.migrate())
        self.network.assert_called_once_with('https://new.example.test/api/enroll', NEW, DEVICE, '1.2.3', '')
        self.assertEqual(self.policy.read_bytes(), b'synthetic policy retained')
        self.assertEqual(self.key.read_bytes(), b'synthetic pinned public key retained')

    def test_absent_intent_and_exact_same_url_do_not_enroll(self):
        self.assertIsNone(self.migrate())
        self.request({'server':'https://old.example.test/api/enroll'})
        self.assertIsNone(self.migrate())
        self.network.assert_not_called()
        self.assertEqual(self.reporting.read_bytes(), self.before)

    def test_same_origin_wrong_report_path_requires_migration(self):
        config.write_config(self.root, credentials('https://new.example.test/other/v1/reports'), os.geteuid())
        self.request()
        self.assertEqual(self.migrate()['report_url'], NEW)
        self.network.assert_called_once()

    def test_strict_intent_and_url_validation(self):
        for value in ({}, [], {'server_url':None}, {'server_url':'http://new.example.test'},
                      {'server_url':'https://new.example.test?x=1'}, {'server_url':'https://new.example.test:99999'},
                      {'server_url':'https://new.example.test/other'}, {'server_url':'https://user:pass@new.example.test'},
                      {'server_url':'https://new.example.test', 'server':'https://other.example.test'}):
            self.request(value)
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError): self.migrate()
        self.network.assert_not_called()
        self.assertEqual(self.reporting.read_bytes(), self.before)

    def test_unsafe_or_malformed_intent_refused_before_network(self):
        original = self.root/'intent-original'; original.write_text('{}'); original.chmod(0o600)
        for kind in ('symlink', 'hardlink', 'fifo', 'permissions', 'duplicate', 'huge', 'deep', 'utf8'):
            if kind == 'symlink': self.intent.symlink_to(original)
            elif kind == 'hardlink': os.link(original, self.intent)
            elif kind == 'fifo': os.mkfifo(self.intent)
            else:
                self.request()
                if kind == 'permissions': self.intent.chmod(0o644)
                elif kind == 'duplicate': self.intent.write_bytes(b'{"server":"a","server":"b"}')
                elif kind == 'huge': self.intent.write_bytes(b'x'*(config.MAX_CONFIG_BYTES+1))
                elif kind == 'deep': self.intent.write_bytes(b'['*2000+b']'*2000)
                else: self.intent.write_bytes(b'\xff')
            with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)): self.migrate()
            self.intent.unlink()
        self.network.assert_not_called()
        self.assertEqual(self.reporting.read_bytes(), self.before)

    def test_device_credentials_and_custom_destinations_cannot_be_bypassed(self):
        self.request()
        for kwargs in ({'device_enrollment':True}, {'report_config':str(self.root/'other.json')}):
            with self.assertRaises(ValueError): self.migrate(**kwargs)
        self.network.assert_not_called()
        self.assertEqual(self.reporting.read_bytes(), self.before)

    def test_failed_transport_preserves_all_local_state(self):
        self.request(); self.network.side_effect = enrollment.EnrollmentError('enrollment_unavailable')
        with self.assertRaises(ValueError): self.migrate()
        self.assertEqual(self.reporting.read_bytes(), self.before)
        self.assertEqual(self.key.read_bytes(), b'synthetic pinned public key retained')

    @unittest.skipUnless(sys.platform=='darwin', 'native Darwin ACL fixture')
    def test_extended_acl_intent_refused_before_network(self):
        self.request()
        subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(self.intent)], check=True, capture_output=True)
        with self.assertRaisesRegex(ValueError, 'extended_acl'): self.migrate()
        self.network.assert_not_called()
        self.assertEqual(self.reporting.read_bytes(), self.before)

    def test_direct_mac_enrollment_uses_validated_transport_without_policy_writes(self):
        spec=importlib.util.spec_from_file_location('direct_enrollment_fixture_agent', DL/'aegis_agent.py')
        agent=importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
        agent.BASE_DIR=self.root
        with patch.object(agent.sys,'platform','darwin'), patch.dict(os.environ,{'AEGIS_ENROLLMENT_SECRET':''}):
            rep, policy=agent.enroll_to_server('https://new.example.test', DEVICE)
        self.assertEqual(rep, credentials(NEW)); self.assertIsNone(policy)
        self.network.assert_called_once_with('https://new.example.test/api/enroll', NEW, DEVICE, agent.AGENT_VERSION, '')
        self.assertEqual(self.reporting.read_bytes(), self.before)
        self.assertEqual(self.key.read_bytes(), b'synthetic pinned public key retained')

    def test_changed_intent_or_credentials_during_network_refuses_commit(self):
        self.request()
        def changed_intent(*args):
            self.request({'server':'https://other.example.test'})
            return credentials(NEW)
        self.network.side_effect = changed_intent
        with self.assertRaisesRegex(ValueError, 'migration_request_changed'): self.migrate()
        self.assertEqual(self.reporting.read_bytes(), self.before)
        self.request()
        def changed_config(*args):
            config.write_config(self.root, credentials('https://admin.example.test/aegis/v1/reports'), os.geteuid())
            return credentials(NEW)
        self.network.side_effect = changed_config
        with self.assertRaisesRegex(ValueError, 'configuration_changed'): self.migrate()
        self.assertEqual(config.read_config(self.reporting)['report_url'], 'https://admin.example.test/aegis/v1/reports')

    def test_directory_sync_failure_returns_applied_not_false_preservation(self):
        self.request()
        real_sync = config.os.fsync
        calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls)==2: raise OSError('synthetic sync failure')
            return real_sync(fd)
        with patch.object(config.os, 'fsync', side_effect=sync): result=self.migrate()
        self.assertEqual(result['_migration_status'], 'applied_durability_unconfirmed')
        self.assertEqual(config.read_config(self.reporting)['report_url'], NEW)

    def test_runtime_dispatch_keeps_failure_state_and_selects_committed_credentials(self):
        spec=importlib.util.spec_from_file_location('migration_fixture_agent', DL/'aegis_agent.py')
        agent=importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
        agent.BASE_DIR=self.root
        args=types.SimpleNamespace(report_url=OLD, report_config=str(self.reporting), enrollment_config='', enrollment_dir='')
        real_migrate=enrollment.migrate
        def invoke(*a, **kw): return real_migrate(*a, **kw, owner=os.geteuid())
        acl = contextlib.nullcontext() if sys.platform=='darwin' else patch.object(config,'require_no_acl')
        with acl, patch.object(agent.sys,'platform','darwin'), patch.object(enrollment,'migrate',side_effect=invoke), patch.dict(os.environ,{'AEGIS_ENROLLMENT_SECRET':''}), patch.object(agent,'enroll_to_server') as legacy:
            self.request()
            args.enrollment_config='synthetic-device-config'
            self.assertIs(agent.apply_server_override(args, DEVICE),False)
            self.assertEqual(args.report_url,OLD)
            args.enrollment_config=''
            result=agent.apply_server_override(args, DEVICE)
            self.assertIsInstance(result,dict)
            self.assertEqual(args.report_url,NEW)
            self.assertEqual(args.report_config,str(self.reporting))
            legacy.assert_not_called()


if __name__=='__main__': unittest.main()
