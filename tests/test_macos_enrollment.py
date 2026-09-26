"""Synthetic enrollment transport/state; never host credentials or a real collector."""
import contextlib
from email.message import Message
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

DL = Path(__file__).resolve().parents[1] / 'public/downloads'
sys.path.insert(0, str(DL))
import aegis_macos_configuration as config
import aegis_macos_enrollment as enrollment

COLLECTOR = 'https://aegis.example.test/aegis'
ENDPOINT = 'https://aegis.example.test/api/enroll'
REPORT = COLLECTOR + '/v1/reports'
DEVICE = '012345abcdef'
VERSION = '1.2.3'


def response_value():
    return {'schema': 'aegis.enrollment/v1', 'report_url': REPORT, 'device_id': DEVICE,
            'report_token': 'synthetic-token-' * 4, 'signing_secret': 'synthetic-signing-' * 4}


class Response:
    def __init__(self, value=None, body=None):
        self.body = json.dumps(response_value() if value is None else value).encode() if body is None else body
        self.headers = Message()
        self.headers['Content-Type'] = 'application/json'
        self.status = 200
        self.url = ENDPOINT
        self.read_limits = []
        self.closed = False
    def geturl(self): return self.url
    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]
    def __enter__(self): return self
    def __exit__(self, *args): self.closed = True


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='aegis-enrollment-fixture-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.reporting = self.root / 'reporting.json'
        self.policy = self.root / 'aegis-policy.json'
        self.policy.write_bytes(b'synthetic active policy')
        self.ui = self.root / 'config.json'
        self.ui.write_bytes(b'synthetic legacy UI state')
        self.ui.chmod(0o600)
        self.response = Response()
        self.opener = Mock()
        self.opener.open.return_value = self.response
        self.factory = patch.object(enrollment.urllib.request, 'build_opener', return_value=self.opener)
        self.factory_mock = self.factory.start()
        self.addCleanup(self.factory.stop)

    def configure(self, **kwargs):
        return enrollment.configure(self.root, kwargs.get('collector', COLLECTOR), kwargs.get('endpoint', ENDPOINT),
                                    kwargs.get('device', DEVICE), kwargs.get('interval', '3600'),
                                    kwargs.get('token', ''), kwargs.get('version', VERSION), owner=os.geteuid(),
                                    enrollment_key=kwargs.get('key', ''))

    def test_success_writes_only_protected_reporting_configuration(self):
        value = {**response_value(), 'policy': {'untrusted': 'must not replace active policy'},
                 'ed25519_public': 'not an independently pinned trust anchor'}
        self.response = Response(value)
        self.opener.open.return_value = self.response
        self.assertEqual(self.configure(key='synthetic-enrollment-' * 3), 'configured_health_pending')
        current = config.read_config(self.reporting, os.geteuid())
        self.assertEqual(current['report_token'], value['report_token'])
        self.assertEqual(self.reporting.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.policy.read_bytes(), b'synthetic active policy')
        self.assertEqual(self.ui.read_bytes(), b'synthetic legacy UI state')
        self.assertFalse((self.root / 'ed25519-public.b64').exists())
        request = self.opener.open.call_args.args[0]
        self.assertEqual(json.loads(request.data), {'device_id': DEVICE, 'agent_version': VERSION})
        self.assertEqual(request.get_header('X-aegis-enrollment-key'), 'synthetic-enrollment-' * 3)
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 25)
        self.assertIsInstance(self.factory_mock.call_args.args[0], enrollment.NoRedirect)
        self.assertEqual(self.response.read_limits, [enrollment.MAX_RESPONSE_BYTES+1])
        self.assertTrue(self.response.closed)

    def test_valid_existing_config_is_preserved_without_network(self):
        self.configure()
        before = self.reporting.read_bytes(), self.reporting.stat().st_mtime_ns
        self.opener.open.reset_mock()
        self.assertEqual(self.configure(), 'preserved_health_pending')
        self.opener.open.assert_not_called()
        self.assertEqual((self.reporting.read_bytes(), self.reporting.stat().st_mtime_ns), before)

    def test_cross_server_or_path_existing_state_requires_migration(self):
        for url in ('https://aegis.example.test.attacker.test/aegis/v1/reports', COLLECTOR+'/different', 'https://other.example.test/aegis/v1/reports'):
            value = enrollment.response_config(response_value(), REPORT, DEVICE)
            config.write_config(self.root, {**value, 'report_url': url}, os.geteuid())
            before = self.reporting.read_bytes()
            with self.assertRaisesRegex(enrollment.EnrollmentError, 'server_migration_required'): self.configure()
            self.assertEqual(self.reporting.read_bytes(), before)
        self.opener.open.assert_not_called()

    def test_malformed_existing_state_is_replaced_only_after_valid_response(self):
        self.reporting.write_bytes(b'invalid synthetic JSON'); self.reporting.chmod(0o600)
        self.opener.open.side_effect = OSError('synthetic private error')
        with self.assertRaises(enrollment.EnrollmentError): self.configure()
        self.assertEqual(self.reporting.read_bytes(), b'invalid synthetic JSON')
        self.opener.open.side_effect = None
        self.assertEqual(self.configure(), 'configured_health_pending')

    def test_invalid_inputs_refused_before_network_and_writes(self):
        for change in ({'collector': 'http://aegis.example.test/aegis'}, {'endpoint': 'https://other.example.test/enroll'},
                       {'collector': 'https://aegis.example.test:99999/aegis'}, {'device': 'hostname'},
                       {'interval': '0'}, {'interval': '1e3'}, {'version': 'not-a-version'},
                       {'token': 'synthetic-manual-'*4}, {'key': 'short'}):
            with self.subTest(field=tuple(change)), self.assertRaises((enrollment.EnrollmentError, config.ConfigurationError)):
                self.configure(**change)
            self.assertFalse(self.reporting.exists())
        self.opener.open.assert_not_called()

    def test_missing_invalid_independent_or_redirected_response_credentials_refused(self):
        base = response_value()
        variants = [{k:v for k,v in base.items() if k != field} for field in base]
        variants += [{**base, **change} for change in ({'device_id': 'abcdef012345'}, {'signing_secret': base['report_token']},
                     {'report_token': 'short'}, {'signing_secret': '密'*32}, {'report_url': REPORT+'?leak=fixture'},
                     {'report_url': 'https://other.example.test/report'}, {'unknown': True}, {'schema': 'other'})]
        for value in variants:
            self.opener.open.return_value = Response(value)
            with self.assertRaises((enrollment.EnrollmentError, config.ConfigurationError)): self.configure()
            self.assertFalse(self.reporting.exists())

    def test_transport_metadata_and_bounded_body_are_required(self):
        for mode in ('status', 'url', 'content-type', 'encoding', 'oversize-header', 'invalid-length', 'duplicate-length', 'length-mismatch', 'oversize-body'):
            response = Response()
            if mode == 'status': response.status = 202
            elif mode == 'url': response.url = 'https://other.example.test/enroll'
            elif mode == 'content-type': response.headers.replace_header('Content-Type', 'text/html')
            elif mode == 'encoding': response.headers['Content-Encoding'] = 'gzip'
            elif mode == 'oversize-header': response.headers['Content-Length'] = str(enrollment.MAX_RESPONSE_BYTES+1)
            elif mode == 'invalid-length': response.headers['Content-Length'] = '-1'
            elif mode == 'duplicate-length': response.headers['Content-Length'] = '1'; response.headers['Content-Length'] = '1'
            elif mode == 'length-mismatch': response.headers['Content-Length'] = '1'
            else: response.body = b'x' * (enrollment.MAX_RESPONSE_BYTES+1)
            self.opener.open.return_value = response
            with self.subTest(mode=mode), self.assertRaises(enrollment.EnrollmentError): self.configure()
            self.assertFalse(self.reporting.exists())
            self.assertTrue(response.closed)

    def test_duplicate_deep_non_utf8_and_incomplete_responses_are_fixed_errors(self):
        for body in (b'{"schema":"a","schema":"b"}', b'['*2000+b']'*2000, b'\xff'):
            self.opener.open.return_value = Response(body=body)
            with self.assertRaisesRegex(enrollment.EnrollmentError, 'invalid_enrollment_response'): self.configure()
        self.opener.open.side_effect = http.client.IncompleteRead(b'synthetic-private-response')
        with self.assertRaises(enrollment.EnrollmentError) as error: self.configure()
        self.assertNotIn('synthetic', str(error.exception))
        self.assertFalse(self.reporting.exists())

    def test_redirects_are_never_followed(self):
        for code in (301,302,303,307,308):
            with self.assertRaisesRegex(enrollment.EnrollmentError, 'redirect_refused'):
                enrollment.NoRedirect().redirect_request(None,None,code,'',{},'https://other.example.test')

    def test_unsafe_existing_file_never_reaches_network(self):
        original = self.root/'original'; original.write_bytes(b'synthetic retained state'); original.chmod(0o600)
        for kind in ('symlink','hardlink','fifo','mode'):
            if kind == 'symlink': self.reporting.symlink_to(original)
            elif kind == 'hardlink': os.link(original,self.reporting)
            elif kind == 'fifo': os.mkfifo(self.reporting)
            else: self.reporting.write_bytes(b'private'); self.reporting.chmod(0o644)
            with self.assertRaises((OSError, config.ConfigurationError)): self.configure()
            self.reporting.unlink()
        self.opener.open.assert_not_called()
        self.assertEqual(original.read_bytes(),b'synthetic retained state')

    def test_configuration_changed_during_request_is_not_overwritten(self):
        replacement = {**enrollment.response_config(response_value(), REPORT, DEVICE), 'report_token':'synthetic-replacement-'*3}
        def request(*args, **kwargs):
            config.write_config(self.root,replacement,os.geteuid())
            return self.response
        self.opener.open.side_effect = request
        with self.assertRaisesRegex(config.ConfigurationError, 'configuration_changed'): self.configure()
        self.assertEqual(config.read_config(self.reporting,os.geteuid()),replacement)

    def test_main_is_fixed_output_and_reports_applied_durability_truthfully(self):
        args=[str(self.root),COLLECTOR,ENDPOINT,DEVICE,'3600','',VERSION]
        for status,code,applied in (('configured_health_pending',0,True),('preserved_health_pending',0,False),('applied_durability_unconfirmed',1,True)):
            with patch.object(sys,'platform','darwin'),patch.object(os,'geteuid',return_value=0),patch.object(enrollment,'configure',return_value=status),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(enrollment.main(args,self.root),code)
                value=json.loads(output.getvalue()); self.assertEqual(value['applied'],applied); self.assertFalse(value['health_verified'])
                self.assertNotIn(str(self.root),output.getvalue()); self.assertNotIn(DEVICE,output.getvalue())
        with patch.object(os,'geteuid',return_value=501),patch.object(enrollment,'configure') as configure,contextlib.redirect_stdout(io.StringIO()):
            self.assertNotEqual(enrollment.main(args,self.root),0)
            configure.assert_not_called()

    @unittest.skipUnless(sys.platform=='darwin' and os.geteuid()==0 and os.environ.get('AEGIS_FROZEN_AGENT'),'root CI and explicit frozen artifact')
    def test_frozen_preservation_and_offline_failure_without_external_runtime(self):
        binary=self.root/'aegis-agent'; shutil.copy2(os.environ['AEGIS_FROZEN_AGENT'],binary); binary.chmod(0o755)
        value=enrollment.response_config(response_value(),REPORT,DEVICE)
        config.write_config(self.root,value,0)
        before=self.reporting.read_bytes()
        profile='(version 1)(allow default)(deny network*)(deny process-exec (require-not (literal (param "BINARY"))))'
        args=[str(binary),'--install-config',str(self.root),COLLECTOR,ENDPOINT,DEVICE,'3600','',VERSION]
        command=['/usr/bin/sandbox-exec','-D','BINARY='+str(binary),'-p',profile]
        env={**os.environ,'PATH':'/nonexistent','PYTHONHOME':'/nonexistent','PYTHONPATH':'/nonexistent'}
        result=subprocess.run(command+args,env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'preserved_health_pending')
        self.assertEqual(self.reporting.read_bytes(),before)
        self.reporting.write_bytes(b'invalid synthetic state')
        result=subprocess.run(command+args,env=env,capture_output=True,text=True,timeout=30)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout)['status'],'enrollment_unavailable')
        self.assertEqual(self.reporting.read_bytes(),b'invalid synthetic state')
        self.assertNotIn('synthetic',result.stdout+result.stderr)


if __name__=='__main__': unittest.main()
