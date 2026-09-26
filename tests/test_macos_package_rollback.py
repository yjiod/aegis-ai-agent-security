"""Rollback through approved package identity, with no real Installer/services."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import test_macos_mdm_install as fixture
ROOT = fixture.ROOT


@unittest.skipUnless(sys.platform == 'darwin', 'Mac system metadata tools and sandbox')
class PackageRollbackTests(unittest.TestCase):
    script_path = ROOT/'public/downloads/rollback-aegis-macos.sh'
    write_assessment = fixture.MacMdmInstallTests.write_assessment
    write_capability = fixture.MacMdmInstallTests.write_capability
    run_script = fixture.MacMdmInstallTests.run_script
    records = fixture.MacMdmInstallTests.records
    assert_no_install = fixture.MacMdmInstallTests.assert_no_install
    user_legacy = fixture.MacMdmInstallTests.user_legacy

    def setUp(self):
        fixture.MacMdmInstallTests.setUp(self)
        self.app = self.root/'Library/Application Support/AegisAgent'
        self.app.mkdir(parents=True)
        self.current = self.app/'aegis-agent'
        # Deliberately unlaunchable: rollback must not execute the damaged client.
        self.current.write_bytes(b'synthetic damaged current executable')
        self.current.chmod(0o600)
        self.current_sha = hashlib.sha256(self.current.read_bytes()).hexdigest()
        self.env.update(AEGIS_MACOS_ROLLBACK_CURRENT_SHA256=self.current_sha,
                        AEGIS_MACOS_ROLLBACK_TARGET_VERSION='1.0.0')
        self.write_capability(agent_version='1.0.0', package_recovery='native-reinstall-v1')
        self.info = self.root/'PackageInfo'
        self.info.write_text('<pkg-info identifier="com.aegis.agent" version="1.0.0" install-location="/"/>')
        self.env['AEGIS_TEST_PACKAGE_INFO'] = str(self.info)

    def test_install_entry_cannot_silently_apply_rollback_parameters(self):
        self.wrapper.write_text(self.wrapper.read_text().replace('OPERATION=rollback\n','OPERATION=install\n',1))
        result,value=self.run_script()
        self.assertEqual(result.returncode,2)
        self.assertEqual(value['status'],'rollback_parameters_require_rollback_entry')
        self.assert_no_install();self.assertFalse(any(c[0]=='curl' for c in self.records()))

    def test_approved_target_reinstalls_without_executing_broken_current(self):
        before=self.current.read_bytes()
        result,value=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(value['operation'],'rollback')
        self.assertEqual(value['status'],'rollback_installed_health_pending')
        self.assertEqual(value['target_version'],'1.0.0')
        self.assertTrue(value['installer_succeeded']);self.assertFalse(value['health_verified'])
        self.assertEqual(self.current.read_bytes(),before)  # Installer is a fixture.
        calls=self.records()
        signature=next(i for i,c in enumerate(calls) if c[:2]==['pkgutil','--check-signature'])
        expansion=next(i for i,c in enumerate(calls) if c[:2]==['pkgutil','--expand'])
        install=next(i for i,c in enumerate(calls) if c[0]=='installer')
        self.assertLess(signature,expansion);self.assertLess(expansion,install)
        self.assertTrue(all(c[1]=='print' for c in calls if c[0]=='launchctl'))

    def test_explicit_current_and_target_arguments_are_required_and_validated(self):
        self.env.pop('AEGIS_MACOS_ROLLBACK_CURRENT_SHA256')
        self.assertEqual(self.run_script()[1]['status'],'rollback_current_digest_required')
        self.env['AEGIS_MACOS_ROLLBACK_CURRENT_SHA256']=self.current_sha
        for version in ('','1.0','1.0.0\nsynthetic-private','1.0.0"','x'*65):
            self.env['AEGIS_MACOS_ROLLBACK_TARGET_VERSION']=version
            result,value=self.run_script()
            self.assertEqual(result.returncode,2);self.assertEqual(value['status'],'rollback_target_version_required')
            self.assertEqual(value['target_version'],'')
        self.assertFalse(any(c[0]=='curl' for c in self.records()))
        self.env.pop('AEGIS_MACOS_ROLLBACK_TARGET_VERSION')
        result,value=self.run_script('-TargetVersion','1.0.0','-CurrentSha256',self.current_sha)
        self.assertEqual(result.returncode,0);self.assertEqual(value['target_version'],'1.0.0')

    def test_current_digest_mismatch_before_download_and_after_assessment(self):
        self.env['AEGIS_MACOS_ROLLBACK_CURRENT_SHA256']='0'*64
        self.assertEqual(self.run_script()[1]['status'],'rollback_current_runtime_mismatch')
        self.assertFalse(any(c[0]=='curl' for c in self.records()))
        self.env['AEGIS_MACOS_ROLLBACK_CURRENT_SHA256']=self.current_sha
        self.env['AEGIS_TEST_CHANGE_CURRENT']=str(self.current)
        self.assertEqual(self.run_script()[1]['status'],'rollback_current_runtime_mismatch')
        self.assert_no_install()

    def test_explicit_absence_repairs_missing_canonical_but_not_a_new_file_or_link(self):
        self.env['AEGIS_MACOS_ROLLBACK_CURRENT_SHA256']='absent'
        self.assertEqual(self.run_script()[1]['status'],'rollback_current_runtime_mismatch')
        self.current.unlink();self.current.symlink_to('missing')
        self.assertEqual(self.run_script()[1]['status'],'rollback_current_runtime_mismatch')
        self.current.unlink()
        self.assertEqual(self.run_script()[1]['status'],'rollback_installed_health_pending')

    def test_rollback_requires_explicit_package_source_not_latest_default(self):
        self.env['AEGIS_MACOS_PKG_URL']=''
        self.assertEqual(self.run_script()[1]['status'],'rollback_package_source_required')
        self.assertFalse(any(c[0]=='curl' for c in self.records()));self.assert_no_install()

    def test_current_links_permissions_acl_and_absence_refuse_without_download(self):
        original=self.current.read_bytes()
        for kind in ('symlink','hardlink','writable','acl','missing'):
            with self.subTest(kind=kind):
                self.current.unlink(missing_ok=True)
                outside=self.root/'original';outside.write_bytes(original)
                if kind=='symlink':self.current.symlink_to(outside)
                elif kind=='hardlink':os.link(outside,self.current)
                elif kind!='missing':
                    self.current.write_bytes(original);self.current.chmod(0o666 if kind=='writable' else 0o600)
                    if kind=='acl':subprocess.run(['/bin/chmod','+a','everyone allow read',str(self.current)],check=True,capture_output=True)
                self.assertEqual(self.run_script()[1]['status'],'unsafe_rollback_current_runtime')
        self.assertFalse(any(c[0]=='curl' for c in self.records()));self.assert_no_install()

    def test_user_migration_is_not_silently_combined_with_rollback(self):
        self.assertEqual(self.run_script('-MigrateUserServices','1')[1]['status'],'rollback_cannot_migrate_user_services')
        self.assert_no_install();self.assertFalse(any(c[0]=='curl' for c in self.records()))
        self.user_legacy()
        self.assertEqual(self.run_script()[1]['status'],'legacy_service_migration_required')
        self.assert_no_install()

    def test_missing_or_wrong_recovery_contract_and_version_refuse_installer(self):
        for extra,status in (({},'rollback_package_contract_required'),
                             ({'agent_version':'1.0.0','package_recovery':'unknown'},'rollback_target_contract_mismatch'),
                             ({'agent_version':'2.0.0','package_recovery':'native-reinstall-v1'},'rollback_target_contract_mismatch')):
            self.write_capability(**extra)
            self.assertEqual(self.run_script()[1]['status'],status)
        self.assert_no_install()

    def test_package_metadata_must_match_target_identity_and_root_location(self):
        for info in ('<pkg-info identifier="other" version="1.0.0" install-location="/"/>',
                     '<pkg-info identifier="com.aegis.agent" version="2.0.0" install-location="/"/>',
                     '<pkg-info identifier="com.aegis.agent" version="1.0.0" install-location="/other"/>',
                     '<pkg-info', 'x'*8193,
                     '<!DOCTYPE pkg-info [<!ENTITY x SYSTEM "file:///synthetic-private">]><pkg-info/>'):
            self.info.write_text(info)
            self.assertEqual(self.run_script()[1]['status'],'rollback_package_metadata_invalid')
        self.assert_no_install()

    def test_invalid_publisher_and_changed_postinstall_cannot_reach_installer(self):
        self.env['AEGIS_TEST_TEAM']='OTHERTEAM1'
        self.assertEqual(self.run_script()[1]['status'],'package_publisher_mismatch')
        self.env.pop('AEGIS_TEST_TEAM')
        self.postinstall.write_bytes(b'changed script')
        self.assertEqual(self.run_script()[1]['status'],'migration_script_digest_mismatch')
        self.assert_no_install()

    def test_installer_failure_is_partial_and_not_automatic_recovery(self):
        self.env['AEGIS_TEST_INSTALLER_RC']='7'
        result,value=self.run_script()
        self.assertEqual(result.returncode,1)
        self.assertEqual(value['status'],'installer_failed_state_requires_verification')
        self.assertTrue(value['installation_attempted']);self.assertFalse(value['installer_succeeded'])

    def test_real_pkg_metadata_passes_after_fixture_signature_gates(self):
        payload=self.root/'payload';payload.mkdir();(payload/'fixture').write_bytes(b'synthetic')
        scripts=self.root/'scripts';scripts.mkdir()
        (scripts/'postinstall').write_bytes(self.postinstall.read_bytes());(scripts/'postinstall').chmod(0o755)
        (scripts/'aegis-package-capabilities.json').write_bytes(self.capability.read_bytes())
        package=self.root/'real.pkg'
        subprocess.run(['/usr/bin/pkgbuild','--root',str(payload),'--scripts',str(scripts),'--identifier','com.aegis.agent',
                        '--version','1.0.0','--install-location','/',str(package)],check=True,capture_output=True,timeout=30)
        self.env.update(AEGIS_TEST_REAL_EXPAND='1',AEGIS_TEST_PACKAGE=str(package),AEGIS_MACOS_PKG_SHA256=hashlib.sha256(package.read_bytes()).hexdigest())
        result,value=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(value['status'],'rollback_installed_health_pending')


if __name__=='__main__':unittest.main()
