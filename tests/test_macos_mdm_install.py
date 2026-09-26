"""MDM bootstrap boundaries; Installer is always a fixture, never a host install."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "public/downloads/mdm-macos-install.sh"
TEAM = "TESTTEAM01"


@unittest.skipUnless(sys.platform == "darwin", "macOS system tools and sandbox")
class MacMdmInstallTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="aegis-mdm-fixture-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.stages = self.root / "stages"
        self.stages.mkdir()
        self.package = self.root / "synthetic.pkg"
        self.package.write_bytes(b"synthetic-package")
        self.package.chmod(0o600)
        self.calls = self.root / "calls"
        self.assessment = self.root / "assessment.plist"
        self.write_assessment()
        self.existing = self.root / "existing-installation"
        self.existing.mkdir()
        for name in ("aegis-agent", "reporting.json", "aegis-policy.json", "service-state"):
            (self.existing / name).write_bytes(b"synthetic-existing-state")
        self.before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.existing.iterdir()}
        mock = '''#!/bin/sh
command=${0##*/}
printf '%s\\0' "$command" "$@" >> "$AEGIS_TEST_CALLS"
printf '\\0' >> "$AEGIS_TEST_CALLS"
case "$command" in
id) printf '%s\\n' "${AEGIS_TEST_UID:-0}";;
launchctl) exit "${AEGIS_TEST_LEGACY_RC:-113}";;
stat)
  if [ "$2" = '%u' ]; then printf '%s\\n' "${AEGIS_TEST_OWNER:-0}"; else exec /usr/bin/stat "$@"; fi;;
curl)
  [ "${AEGIS_TEST_DOWNLOAD_RC:-0}" = 0 ] || { echo 'synthetic-private-download-error' >&2; exit "$AEGIS_TEST_DOWNLOAD_RC"; }
  while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; output=$1; fi; shift; done
  /bin/cp -P -X "$AEGIS_TEST_PACKAGE" "$output";;
pkgutil)
  if [ "$1" = --expand ]; then
    if [ "${AEGIS_TEST_REAL_EXPAND:-0}" = 1 ]; then exec /usr/sbin/pkgutil "$@"; fi
    [ "${AEGIS_TEST_EXPANSION_RC:-0}" = 0 ] || exit "$AEGIS_TEST_EXPANSION_RC"
    /bin/mkdir -p "$3/Scripts"
    if [ -n "${AEGIS_TEST_PACKAGE_INFO:-}" ]; then /bin/cp "$AEGIS_TEST_PACKAGE_INFO" "$3/PackageInfo"; fi
    /bin/cp "$AEGIS_TEST_CAPABILITY" "$3/Scripts/aegis-package-capabilities.json"
    /bin/cp "$AEGIS_TEST_POSTINSTALL" "$3/Scripts/postinstall"
    case "${AEGIS_TEST_EXPANSION_KIND:-normal}" in
      capability-missing) /bin/rm "$3/Scripts/aegis-package-capabilities.json";;
      capability-link) /bin/rm "$3/Scripts/aegis-package-capabilities.json"; /bin/ln -s "$AEGIS_TEST_CAPABILITY" "$3/Scripts/aegis-package-capabilities.json";;
      script-hardlink) /bin/ln "$3/Scripts/postinstall" "$3/Scripts/extra-link";;
      scripts-link) /bin/mv "$3/Scripts" "$3/moved"; /bin/ln -s "$3/moved" "$3/Scripts";;
    esac
    [ "${AEGIS_TEST_EXPANSION_TAMPER:-0}" = 0 ] || printf changed >> "$2"
    exit 0
  fi
  [ "${AEGIS_TEST_SIGNATURE_RC:-0}" = 0 ] || exit "$AEGIS_TEST_SIGNATURE_RC"
  printf 'Package: synthetic\\nStatus: fixture only\\nCertificate Chain:\\n  1. Developer ID Installer: Fixture Publisher (%s)\\n' "${AEGIS_TEST_TEAM:-TESTTEAM01}";;
spctl)
  if [ "$1" = --status ]; then
    printf 'assessments %s\\n' "${AEGIS_TEST_ASSESSMENT_STATE:-enabled}"
    [ "${AEGIS_TEST_ASSESSMENT_STATE:-enabled}" = enabled ]; exit $?
  fi
  [ "${AEGIS_TEST_ASSESSMENT_RC:-0}" = 0 ] || exit "$AEGIS_TEST_ASSESSMENT_RC"
  if [ "${AEGIS_TEST_TAMPER:-0}" = 1 ]; then for package do :; done; printf changed >> "$package"; fi
  if [ -n "${AEGIS_TEST_LATE_LEGACY:-}" ]; then /bin/mkdir -p "${AEGIS_TEST_LATE_LEGACY%/*}"; printf synthetic > "$AEGIS_TEST_LATE_LEGACY"; fi
  if [ -n "${AEGIS_TEST_CHANGE_CURRENT:-}" ]; then printf changed >> "$AEGIS_TEST_CHANGE_CURRENT"; fi
  /bin/cat "$AEGIS_TEST_ASSESSMENT";;
installer)
  printf 'synthetic-private-installer-output\\n'
  exit "${AEGIS_TEST_INSTALLER_RC:-0}";;
*) exit 99;;
esac
'''
        source = getattr(self, "script_path", SCRIPT).read_text()
        for tool, location in (("id", "/usr/bin/id"), ("stat", "/usr/bin/stat"), ("curl", "/usr/bin/curl"),
                               ("pkgutil", "/usr/sbin/pkgutil"), ("spctl", "/usr/sbin/spctl"), ("installer", "/usr/sbin/installer"),
                               ("launchctl", "/bin/launchctl")):
            path = self.bin / tool
            path.write_text(mock)
            path.chmod(0o755)
            source = source.replace(location, '"' + str(path) + '"')
        source = source.replace("/private/var/tmp/aegis-mdm.XXXXXXXX", str(self.stages / "aegis-mdm.XXXXXXXX"))
        source = source.replace("/Library/Application Support/AegisAgent", str(self.root / "Library/Application Support/AegisAgent"))
        source = source.replace("/Library/LaunchDaemons", str(self.root / "Library/LaunchDaemons"))
        source = source.replace("/Users/", str(self.root / "Users") + "/")
        source = source.replace(" /Library ", ' "'+str(self.root/"Library")+'" ')
        source = source.replace("'/Library/Application Support'", "'"+str(self.root/"Library/Application Support")+"'")
        self.wrapper = self.root / "mdm.sh"
        self.wrapper.write_text(source)
        self.env = {**os.environ, "AEGIS_MACOS_PKG_SHA256": hashlib.sha256(self.package.read_bytes()).hexdigest(),
                    "AEGIS_MACOS_TEAM_ID": TEAM, "AEGIS_MACOS_PKG_URL": "https://aegis.example.test/downloads/agent.pkg",
                    "AEGIS_MACOS_PKG_PATH": "", "AEGIS_TEST_PACKAGE": str(self.package),
                    "AEGIS_TEST_CALLS": str(self.calls), "AEGIS_TEST_ASSESSMENT": str(self.assessment),
                    "PATH": "/nonexistent", "PYTHONHOME": "/nonexistent", "PYTHONPATH": "/nonexistent"}
        for name in ("AEGIS_ENROLL_UNINSTALL", "AEGIS_COLLECTOR_URL", "AEGIS_COLLECTOR_TOKEN",
                     "AEGIS_REPORT_SIGNING_SECRET", "AEGIS_SCAN_INTERVAL", "AEGIS_DEVICE_ID", "AEGIS_INSTALL_DIR",
                     "AEGIS_BASE_URL", "AEGIS_MACOS_ROLLBACK_CURRENT_SHA256", "AEGIS_MACOS_ROLLBACK_TARGET_VERSION"):
            self.env.pop(name, None)
        self.postinstall = self.root / "postinstall-fixture"
        self.postinstall.write_bytes(b'#!/bin/sh\nexit 99\n')
        self.capability = self.root / "capability.json"
        self.write_capability()
        self.env.update(AEGIS_MACOS_MIGRATE_USER_SERVICES="0", AEGIS_TEST_CAPABILITY=str(self.capability),
                        AEGIS_TEST_POSTINSTALL=str(self.postinstall))

    def write_capability(self, **changes):
        value = {"schema":"aegis.macos-package-capabilities/v1", "package_identifier":"com.aegis.agent",
                 "legacy_user_services":"journaled-prepare-v1", "external_python_required":False,
                 "postinstall_sha256":hashlib.sha256(self.postinstall.read_bytes()).hexdigest()}
        value.update(changes)
        self.capability.write_text(json.dumps(value))

    def user_legacy(self):
        path = self.root / "Users/fixture/Library/LaunchAgents/com.aegis.agent.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'synthetic retained launch file')
        return path

    def test_explicit_user_migration_checks_verified_package_contract_before_installer(self):
        legacy = self.user_legacy()
        result, value = self.run_script('-MigrateUserServices', '1')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(value['legacy_user_migration_requested'])
        self.assertTrue(value['legacy_user_launch_files_detected'])
        self.assertFalse(value['health_verified'])
        calls = self.records()
        expansion = next(i for i,c in enumerate(calls) if c[:2]==['pkgutil','--expand'])
        signature = next(i for i,c in enumerate(calls) if c[:2]==['pkgutil','--check-signature'])
        assessment = max(i for i,c in enumerate(calls) if c[0]=='spctl')
        install = next(i for i,c in enumerate(calls) if c[0]=='installer')
        self.assertLess(signature, assessment);self.assertLess(assessment, expansion);self.assertLess(expansion, install)
        self.assertTrue(all(c[1]=='print' for c in calls if c[0]=='launchctl'))
        self.assertEqual(legacy.read_bytes(), b'synthetic retained launch file')

    def test_migration_contract_is_required_even_without_discovered_user_files(self):
        self.env['AEGIS_MACOS_MIGRATE_USER_SERVICES']='1'
        result,value=self.run_script()
        self.assertEqual(result.returncode,0)
        self.assertTrue(value['legacy_user_migration_requested']);self.assertFalse(value['legacy_user_launch_files_detected'])
        self.assertTrue(any(c[:2]==['pkgutil','--expand'] for c in self.records()))

    def test_migration_mode_does_not_bypass_signature_or_old_system_service_gates(self):
        self.user_legacy();self.env['AEGIS_MACOS_MIGRATE_USER_SERVICES']='1'
        for field, value, status in (('AEGIS_TEST_SIGNATURE_RC','1','package_signature_rejected'),
                                     ('AEGIS_TEST_LEGACY_RC','0','legacy_service_migration_required')):
            self.env[field]=value
            self.assertEqual(self.run_script()[1]['status'],status)
            self.env.pop(field)
        self.assert_no_install()
        self.assertFalse(any(c[:2]==['pkgutil','--expand'] for c in self.records()))

    def test_legacy_state_appearing_during_assessment_is_rechecked(self):
        for relative,status in (('Users/fixture/Library/LaunchAgents/com.aegis.agent.plist','legacy_service_migration_required'),
                                ('Library/Application Support/AegisAgent/watch-cleanup-pending.json','prior_cleanup_requires_verification')):
            late=self.root/relative
            self.env['AEGIS_TEST_LATE_LEGACY']=str(late)
            result,value=self.run_script()
            self.assertEqual(result.returncode,1);self.assertEqual(value['status'],status)
            self.assertTrue(late.exists());late.unlink()
        self.assert_no_install()

    def test_invalid_migration_mode_refused_before_download(self):
        for mode in ('true','yes','2','-1'):
            self.env['AEGIS_MACOS_MIGRATE_USER_SERVICES']=mode
            result,value=self.run_script()
            self.assertEqual(result.returncode,2);self.assertEqual(value['status'],'invalid_migration_mode')
        self.assertFalse(any(c[0]=='curl' for c in self.records()));self.assert_no_install()

    def test_missing_wrong_or_oversized_capability_refuses_migration_install(self):
        self.user_legacy();self.env['AEGIS_MACOS_MIGRATE_USER_SERVICES']='1'
        for changes in ({'schema':'other'}, {'package_identifier':'com.other'}, {'legacy_user_services':'unknown'},
                        {'external_python_required':True}, {'external_python_required':'false'},
                        {'postinstall_sha256':'not-a-digest'}):
            self.write_capability(**changes)
            self.assertEqual(self.run_script()[1]['status'],'migration_capability_unavailable')
        for contents in ('{}', '{bad json', 'x'*4097):
            self.capability.write_text(contents)
            self.assertEqual(self.run_script()[1]['status'],'migration_capability_unavailable')
        self.write_capability(postinstall_sha256='0'*64)
        self.assertEqual(self.run_script()[1]['status'],'migration_script_digest_mismatch')
        self.assert_no_install()

    def test_expansion_links_failure_or_package_change_never_reach_installer(self):
        self.env['AEGIS_MACOS_MIGRATE_USER_SERVICES']='1'
        for kind in ('capability-missing','capability-link','script-hardlink','scripts-link'):
            self.env['AEGIS_TEST_EXPANSION_KIND']=kind
            self.assertEqual(self.run_script()[1]['status'],'migration_capability_unavailable')
        self.env.pop('AEGIS_TEST_EXPANSION_KIND')
        self.env['AEGIS_TEST_EXPANSION_RC']='1'
        self.assertEqual(self.run_script()[1]['status'],'migration_package_expansion_failed')
        self.env.pop('AEGIS_TEST_EXPANSION_RC')
        self.env['AEGIS_TEST_EXPANSION_TAMPER']='1'
        self.assertEqual(self.run_script()[1]['status'],'package_changed_after_assessment')
        self.assert_no_install()

    def test_real_package_metadata_layout_after_fixture_trust_gates(self):
        payload=self.root/'real-payload';payload.mkdir();(payload/'marker').write_bytes(b'synthetic payload')
        scripts=self.root/'real-scripts';scripts.mkdir()
        (scripts/'postinstall').write_bytes(self.postinstall.read_bytes());(scripts/'postinstall').chmod(0o755)
        (scripts/'aegis-package-capabilities.json').write_bytes(self.capability.read_bytes())
        package=self.root/'real-layout.pkg'
        subprocess.run(['/usr/bin/pkgbuild','--root',str(payload),'--scripts',str(scripts),'--identifier','com.aegis.agent',
                        '--version','1.0.0','--install-location','/Library/Application Support/AegisFixture',str(package)],
                       check=True,capture_output=True,timeout=30)
        legacy=self.user_legacy()
        self.env.update(AEGIS_TEST_REAL_EXPAND='1',AEGIS_MACOS_MIGRATE_USER_SERVICES='1',
                        AEGIS_TEST_PACKAGE=str(package),AEGIS_MACOS_PKG_SHA256=hashlib.sha256(package.read_bytes()).hexdigest())
        result,value=self.run_script()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(value['status'],'installed_health_pending')
        self.assertTrue(value['legacy_user_launch_files_detected'])
        self.assertEqual(legacy.read_bytes(),b'synthetic retained launch file')

    def write_assessment(self, verdict=True, source="Notarized Developer ID", **extra):
        self.assessment.write_bytes(plistlib.dumps({"assessment:verdict": verdict,
            "assessment:authority": {"assessment:authority:source": source, **extra}}))

    def run_script(self, *args):
        profile = '''(version 1)(allow default)(deny network*)
(deny process-exec (regex #"/python[0-9.]*$") (literal "/usr/sbin/installer") (literal "/bin/launchctl"))
(deny file-write* (require-all (require-not (subpath (param "FIXTURE"))) (require-not (literal "/dev/null"))))'''
        result = subprocess.run(["/usr/bin/sandbox-exec", "-D", "FIXTURE=" + str(self.root), "-p", profile, "/bin/sh", str(self.wrapper), *args],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertNotIn("synthetic-private", result.stdout + result.stderr)
        self.assertEqual(self.before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.existing.iterdir()})
        self.assertEqual(list(self.stages.iterdir()), [])
        return result, json.loads(result.stdout)

    def records(self):
        if not self.calls.exists(): return []
        return [[x.decode() for x in item.split(b"\0")] for item in self.calls.read_bytes().split(b"\0\0") if item]

    def assert_no_install(self):
        self.assertNotIn("installer", [x[0] for x in self.records()])

    def test_positive_fixture_orders_gates_before_installer_and_leaves_health_pending(self):
        result, value = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value["status"], "installed_health_pending")
        self.assertTrue(value["installer_succeeded"])
        self.assertFalse(value["health_verified"])
        commands = [x[0] for x in self.records()]
        self.assertLess(commands.index("curl"), commands.index("pkgutil"))
        self.assertLess(commands.index("pkgutil"), commands.index("spctl"))
        self.assertLess(commands.index("spctl"), commands.index("installer"))
        download = next(x for x in self.records() if x[0] == "curl")
        self.assertIn("=https", download)
        self.assertIn("--max-filesize", download)
        self.assertNotIn("--location", download)
        self.assertNotIn("--insecure", download)
        install = next(x for x in self.records() if x[0] == "installer")
        self.assertEqual(install[1], "-pkg")
        self.assertEqual(install[-2:], ["-target", "/"])

    def test_historical_uninstall_setting_never_installs_or_changes_services(self):
        for setting in ("1", "0", "", "synthetic-private-invalid"):
            with self.subTest(setting=setting):
                self.env['AEGIS_ENROLL_UNINSTALL'] = setting
                result, value = self.run_script('-MigrateUserServices', '1')
                self.assertEqual(result.returncode, 2)
                self.assertEqual(value['status'], 'legacy_uninstall_setting_requires_maintenance')
                self.assertFalse(value['installation_attempted'])
        self.assertEqual(self.records(), [])

    def test_old_enrollment_environment_is_not_ignored_or_disclosed(self):
        for name in ('AEGIS_COLLECTOR_URL', 'AEGIS_COLLECTOR_TOKEN', 'AEGIS_REPORT_SIGNING_SECRET',
                     'AEGIS_SCAN_INTERVAL', 'AEGIS_DEVICE_ID', 'AEGIS_INSTALL_DIR'):
            for setting in ('', 'synthetic-private-value\n$(exit 99)'):
                with self.subTest(name=name, empty=not setting):
                    self.env[name] = setting
                    result, value = self.run_script()
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(value['status'], 'legacy_enrollment_settings_not_supported')
                    self.assertFalse(value['installation_attempted'])
                    self.env.pop(name)
        self.assertEqual(self.records(), [])

    def test_base_url_retains_only_package_download_root_semantics(self):
        self.env['AEGIS_MACOS_PKG_URL'] = ''
        self.env['AEGIS_BASE_URL'] = 'https://aegis.example.test/approved'
        result, value = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value['status'], 'installed_health_pending')
        download = next(c for c in self.records() if c[0] == 'curl')
        self.assertIn('https://aegis.example.test/approved/aegis-agent-macos.pkg', download)

    def test_local_cache_does_not_download_or_modify_source(self):
        self.env.update(AEGIS_MACOS_PKG_URL="", AEGIS_MACOS_PKG_PATH=str(self.package))
        before = self.package.read_bytes()
        result, _ = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("curl", [x[0] for x in self.records()])
        self.assertEqual(self.package.read_bytes(), before)

    def test_administrator_arguments_require_pins_and_preserve_validation(self):
        digest = self.env.pop("AEGIS_MACOS_PKG_SHA256")
        self.env.pop("AEGIS_MACOS_TEAM_ID")
        self.env["AEGIS_MACOS_PKG_URL"] = ""
        result, value = self.run_script("-PkgSha256", digest, "-TeamId", TEAM,
                                        "-PkgUrl", "https://aegis.example.test/approved.pkg")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value["status"], "installed_health_pending")
        self.assertEqual(value["artifact_sha256"], digest)

    def test_ambiguous_or_legacy_arguments_do_not_touch_services_or_download(self):
        for args, status in ((("-PkgUrl",), "missing_argument_value"),
                             (("-TeamId", "",), "missing_argument_value"),
                             (("-PkgUrl", "-TeamId"), "missing_argument_value"),
                             (("-TeamId", TEAM, "-TeamId", TEAM), "duplicate_argument"),
                             (("-Server", "https://aegis.example.test"), "unexpected_arguments")):
            result, value = self.run_script(*args)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(value["status"], status)
        self.assertEqual(self.records(), [])

    def test_platform_missing_key_stdout_cannot_pollute_public_result(self):
        probe = self.bin / "plutil"
        probe.write_text('''#!/bin/sh
/usr/bin/plutil "$@"
code=$?
[ "$code" = 0 ] || printf 'synthetic-private-missing-key-error\\n'
exit "$code"
''')
        probe.chmod(0o755)
        self.wrapper.write_text(self.wrapper.read_text().replace("/usr/bin/plutil", '"' + str(probe) + '"'))
        result, value = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(value["status"], "installed_health_pending")

    def test_missing_digest_publisher_and_privilege_refused_before_staging(self):
        for field, replacement in (("AEGIS_MACOS_PKG_SHA256", ""), ("AEGIS_MACOS_PKG_SHA256", 'invalid"input'),
                                   ("AEGIS_MACOS_TEAM_ID", ""), ("AEGIS_MACOS_TEAM_ID", "bad.*"), ("AEGIS_TEST_UID", "501")):
            old = self.env.get(field)
            self.env[field] = replacement
            result, value = self.run_script()
            self.assertEqual(result.returncode, 2)
            self.assertFalse(value["installation_attempted"])
            self.assertNotIn("curl", [x[0] for x in self.records()])
            if old is None: self.env.pop(field)
            else: self.env[field] = old
        self.assertEqual(self.run_script("--extra")[0].returncode, 2)
        self.assert_no_install()

    def test_invalid_urls_never_reach_download(self):
        for url in ("http://aegis.example.test/p.pkg", "https://user@aegis.example.test/p.pkg",
                    "https://aegis.example.test/p.pkg?token=fixture", "https://aegis.example.test/p.pkg\n",
                    "https://aegis.example.test/$(id).pkg", "https://aegis.example.test/p.pkg#fragment"):
            self.env["AEGIS_MACOS_PKG_URL"] = url
            result, value = self.run_script()
            self.assertEqual(value["status"], "invalid_package_url")
            self.assertEqual(result.returncode, 2)
        self.assertNotIn("curl", [x[0] for x in self.records()])

    def test_local_source_conflict_links_permissions_owner_and_oversize_refused(self):
        self.env["AEGIS_MACOS_PKG_PATH"] = str(self.package)
        self.assertEqual(self.run_script()[1]["status"], "ambiguous_package_source")
        self.env["AEGIS_MACOS_PKG_URL"] = ""
        self.env["AEGIS_TEST_OWNER"] = "501"
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        self.env.pop("AEGIS_TEST_OWNER")
        self.package.chmod(0o666)
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        self.package.chmod(0o600)
        alias = self.root / "alias.pkg"
        alias.symlink_to(self.package)
        self.env["AEGIS_MACOS_PKG_PATH"] = str(alias)
        self.assertEqual(self.run_script()[1]["status"], "invalid_local_package")
        alias.unlink(); os.link(self.package, alias)
        self.assertEqual(self.run_script()[1]["status"], "unsafe_local_package")
        alias.unlink()
        with self.package.open("r+b") as f: f.truncate(134217729)
        self.env["AEGIS_MACOS_PKG_PATH"] = str(self.package)
        self.assertEqual(self.run_script()[1]["status"], "package_size_refused")
        self.assert_no_install()

    def test_download_digest_signature_publisher_and_assessment_failures_preserve_existing(self):
        cases = (("AEGIS_TEST_DOWNLOAD_RC", "28", "package_download_failed"),
                 ("AEGIS_MACOS_PKG_SHA256", "0" * 64, "package_digest_mismatch"),
                 ("AEGIS_TEST_SIGNATURE_RC", "1", "package_signature_rejected"),
                 ("AEGIS_TEST_TEAM", "OTHERTEAM1", "package_publisher_mismatch"),
                 ("AEGIS_TEST_ASSESSMENT_STATE", "disabled", "platform_assessment_disabled"),
                 ("AEGIS_TEST_ASSESSMENT_RC", "3", "package_assessment_rejected"),
                 ("AEGIS_TEST_TAMPER", "1", "package_changed_after_assessment"))
        for field, replacement, status in cases:
            old = self.env.get(field)
            self.env[field] = replacement
            result, value = self.run_script()
            self.assertEqual(result.returncode, 1)
            self.assertEqual(value["status"], status)
            self.assertFalse(value["installation_attempted"])
            if old is None: self.env.pop(field)
            else: self.env[field] = old
        self.assert_no_install()

    def test_raw_assessment_cannot_use_override_false_verdict_or_unnotarized_source(self):
        for kwargs, status in (({"verdict": False}, "package_assessment_rejected"),
                               ({"verdict": "true"}, "invalid_package_assessment"),
                               ({"source": "Unnotarized Developer ID"}, "package_notarization_unconfirmed"),
                               ({"assessment:authority:override": "security disabled"}, "package_assessment_override_refused"),
                               ({"assessment:authority:override": ""}, "package_assessment_override_refused"),
                               ({"assessment:authority:verdict": False}, "package_assessment_rejected")):
            self.write_assessment(**kwargs)
            result, value = self.run_script()
            self.assertEqual(result.returncode, 1)
            self.assertEqual(value["status"], status)
        self.assessment.write_text("not a plist")
        self.assertEqual(self.run_script()[1]["status"], "invalid_package_assessment")
        self.assert_no_install()

    def test_installer_failure_is_not_claimed_to_have_rolled_back(self):
        self.env["AEGIS_TEST_INSTALLER_RC"] = "7"
        result, value = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value["status"], "installer_failed_state_requires_verification")
        self.assertTrue(value["installation_attempted"])
        self.assertFalse(value["installer_succeeded"])

    def test_legacy_service_or_pending_cleanup_require_migration_before_download(self):
        for code, status in (("0", "legacy_service_migration_required"), ("1", "legacy_service_state_unavailable")):
            self.env["AEGIS_TEST_LEGACY_RC"] = code
            self.assertEqual(self.run_script()[1]["status"], status)
        self.env.pop("AEGIS_TEST_LEGACY_RC")
        pending = self.root / "Library/Application Support/AegisAgent/watch-cleanup-pending.json"
        pending.parent.mkdir(parents=True)
        pending.symlink_to("missing")
        self.assertEqual(self.run_script()[1]["status"], "prior_cleanup_requires_verification")
        pending.unlink()
        legacy = self.root / "Library/LaunchDaemons/com.company.aegis-agent.plist"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("synthetic legacy state")
        self.assertEqual(self.run_script()[1]["status"], "legacy_service_migration_required")
        self.assertEqual(legacy.read_text(), "synthetic legacy state")
        legacy.unlink()
        user_legacy = self.root / "Users/fixture/Library/LaunchAgents/com.aegis.agent.plist"
        user_legacy.parent.mkdir(parents=True)
        user_legacy.write_text("synthetic user legacy state")
        self.assertEqual(self.run_script()[1]["status"], "legacy_service_migration_required")
        self.assertTrue(user_legacy.exists())
        self.assertNotIn("curl", [x[0] for x in self.records()])
        self.assert_no_install()

    def test_real_unsigned_package_rejected_by_system_signature_check(self):
        payload = self.root / "unsigned-payload"
        payload.mkdir()
        (payload / "fixture.txt").write_text("synthetic payload")
        package = self.root / "unsigned.pkg"
        subprocess.run(["/usr/bin/pkgbuild", "--root", str(payload), "--identifier", "com.aegis.fixture",
                        "--version", "1.0.0", "--install-location", "/Library/Application Support/AegisFixture",
                        str(package)], check=True, capture_output=True, timeout=30)
        self.env.update(AEGIS_MACOS_PKG_URL="", AEGIS_MACOS_PKG_PATH=str(package),
                        AEGIS_MACOS_PKG_SHA256=hashlib.sha256(package.read_bytes()).hexdigest())
        self.wrapper.write_text(self.wrapper.read_text().replace('"' + str(self.bin / "pkgutil") + '"', "/usr/sbin/pkgutil"))
        result, value = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value["status"], "package_signature_rejected")
        self.assert_no_install()


class MacInteractiveInstallTests(MacMdmInstallTests):
    script_path = ROOT / "public/downloads/aegis-install-macos-oneclick.sh"


class MacHistoricalEnrollEntryTests(MacMdmInstallTests):
    script_path = ROOT / "public/downloads/aegis-agent-macos-enroll.sh"


if __name__ == "__main__":
    unittest.main()
