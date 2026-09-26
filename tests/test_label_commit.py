"""Success, failure, lost acknowledgements and concurrent label decisions."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = r"""
exports.NextResponse={json:(body,options={})=>new Response(JSON.stringify(body),options)};
exports.getSession=()=>fixture.auth?{subject:'fixture-admin'}:null;
exports.requireAdmin=()=>fixture.auth?null:new Response('{}',{status:401});
exports.logAudit=entry=>fixture.audits.push(entry);
exports.pgEnabled=()=>true;
exports.pgLoadLabels=()=>fixture.load();
exports.pgApplyLabelChanges=async(patches,onlyUndecided)=>{
  fixture.active++;fixture.maxActive=Math.max(fixture.maxActive,fixture.active);fixture.calls++;
  try {
    if(fixture.gate)await fixture.gate();
    if(fixture.failure==='before')throw new Error('private-storage-detail');
    const rows=[],appliedKeys=[];
    for(const p of patches){
      const k=p.asset_type+':'+p.asset_key,prev=fixture.db.get(k);
      if(onlyUndecided && prev?.disposition){rows.push({...prev});continue;}
      const r={tags:'[]',disposition:'',note:'',...prev,...Object.fromEntries(Object.entries(p).filter(([,v])=>v!==undefined)),
        decision_source:p.disposition!==undefined?(p.decision_source??'manual'):(prev?.decision_source??'legacy')};
      fixture.db.set(k,r);rows.push({...r});appliedKeys.push(k);
    }
    if(fixture.failure==='after')throw new Error('private-ack-detail');
    return {labels:rows,appliedKeys};
  }finally{fixture.active--;}
};
exports.pgDeleteLabel=async(type,key)=>{
  fixture.calls++;
  if(fixture.gate)await fixture.gate();
  if(fixture.failure==='before')throw new Error('private-storage-detail');
  const removed=fixture.db.delete(type+':'+key);
  if(fixture.failure==='after')throw new Error('private-ack-detail');
  return removed;
};
exports.defaultBundledEntries=()=>[{asset_type:'skill',asset_key:'catalog-fixture'}];
exports.getSetting=()=>null;
exports.moduleOverrides=()=>({skill_enforce:false,mcp_enforce:false});
exports.getAlertConfig=()=>({});
exports.ensureBaselinesLoaded=exports.ensurePolicyReleasesLoaded=exports.ensureSigningKeysLoaded=async()=>{};
exports.getScanMode=()=> 'standard';exports.effectiveRules=()=>[];exports.enforceableRuleIds=()=>[];
exports.exemptDevices=exports.pinnedDevices=()=>[];exports.getRollout=()=>({});
exports.publishPolicyRelease=()=>{fixture.published++;return {version:9};};
"""

RUNNER = r"""
const assert=require('node:assert/strict');
const [compiled,scenario]=process.argv.slice(1);
globalThis.fixture={auth:true,db:new Map(),calls:0,active:0,maxActive:0,audits:[],failure:'',published:0};
fixture.load=async()=>[...fixture.db.values()].map(r=>({...r}));
const {labels,api,seed,remediation}=require(compiled);
const row=(key,disposition='allow')=>({asset_type:'skill',asset_key:key,disposition,decision_source:'manual',tags:'[]',note:'',updated_by:'fixture',updated_at:1});
const request=body=>new Request('https://console.example.test/api/labels',{method:'POST',body:JSON.stringify(body)});
const edit=(key,disposition='deny')=>api.POST(request({asset_type:'skill',asset_key:key,disposition}));
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const current=key=>labels.listLabels().find(l=>l.asset_key===key);
const failureResponse=async response=>{
  assert.equal(response.status,503);assert.equal(response.headers.get('Cache-Control'),'no-store');
  const body=await response.json();assert.equal(body.error,'labels_write_unconfirmed');
  assert(!JSON.stringify(body).includes('private-'));
  assert(!JSON.stringify(fixture.audits).includes('private-'));
};
(async()=>{
  if(scenario==='manual'){
    fixture.db.set('skill:fixture',row('fixture'));
    await labels.ensureLabelsLoaded();
    let release;fixture.gate=()=>new Promise(resolve=>{release=resolve});
    let done=false;const pending=edit('fixture').then(r=>{done=true;return r});
    await tick();assert.equal(done,false);assert.equal(current('fixture').disposition,'allow');
    release();const response=await pending;assert.equal(response.status,200);
    assert.equal(current('fixture').disposition,'deny');
    assert.equal(fixture.db.get('skill:fixture').disposition,'deny');
    fixture.gate=null;fixture.failure='before';
    await failureResponse(await edit('fixture','allow'));
    assert.equal(current('fixture').disposition,'deny');
    assert.equal(fixture.audits.filter(a=>a.action==='label:set').length,1);
    fixture.failure='';assert.equal((await edit('fixture','allow')).status,200);
    assert.equal(current('fixture').disposition,'allow');
  }else if(scenario==='lost-ack'){
    fixture.db.set('skill:fixture',row('fixture'));
    await labels.ensureLabelsLoaded();const stale=labels.allowedAssetKeys();
    fixture.failure='after';await failureResponse(await edit('fixture'));
    assert.equal(current('fixture').disposition,'allow'); // no unacknowledged cache advance
    assert.equal(fixture.db.get('skill:fixture').disposition,'deny');
    assert.equal(labels.isFindingAllowed({asset_type:'skill',asset_key:'fixture',kind:'prompt_override'},stale),false);
    fixture.failure='';await labels.ensureLabelsLoaded();
    assert.equal(current('fixture').disposition,'deny');
    fixture.failure='after';
    await failureResponse(await api.DELETE(new Request('https://console.example.test/api/labels?asset_type=skill&asset_key=fixture')));
    assert(current('fixture'));assert.equal(fixture.db.has('skill:fixture'),false);
    fixture.failure='';await labels.ensureLabelsLoaded();assert.equal(current('fixture'),undefined);
    // A database row absent from the process snapshot must still be deleted.
    fixture.db.set('skill:remote',row('remote'));
    const response=await api.DELETE(new Request('https://console.example.test/api/labels?asset_type=skill&asset_key=remote'));
    assert.equal((await response.json()).removed,true);assert.equal(fixture.db.has('skill:remote'),false);
  }else if(scenario==='delete'){
    fixture.db.set('skill:fixture',row('fixture'));await labels.ensureLabelsLoaded();
    let release;fixture.gate=()=>new Promise(resolve=>{release=resolve});fixture.failure='before';
    const del=()=>api.DELETE(new Request('https://console.example.test/api/labels?asset_type=skill&asset_key=fixture'));
    let done=false;const pending=del().then(r=>{done=true;return r});await tick();
    assert.equal(done,false);assert(current('fixture'));release();await failureResponse(await pending);
    assert(current('fixture'));assert(fixture.db.has('skill:fixture'));
    fixture.gate=null;fixture.failure='';assert.equal((await (await del()).json()).removed,true);
    assert.equal(current('fixture'),undefined);assert.equal((await (await del()).json()).removed,false);
  }else if(scenario==='seed'){
    fixture.failure='before';
    await failureResponse(await seed.POST(new Request('https://console.example.test/api/labels/seed-defaults',{method:'POST'})));
    assert.equal(current('catalog-fixture'),undefined);
    fixture.failure='';
    const response=await seed.POST(new Request('https://console.example.test/api/labels/seed-defaults',{method:'POST'}));
    assert.deepEqual(await response.json(),{ok:true,seeded:1,skipped:0});
    assert.equal(current('catalog-fixture').decision_source,'preset');
  }else if(scenario==='concurrent'){
    await labels.ensureLabelsLoaded();
    let release;fixture.gate=()=>new Promise(resolve=>{release=resolve});
    const first=edit('fixture','deny');await tick();
    const second=edit('fixture','allow');await tick();assert.equal(fixture.calls,1);
    fixture.gate=null;release();assert.equal((await first).status,200);assert.equal((await second).status,200);
    assert.equal(fixture.maxActive,1);assert.equal(current('fixture').disposition,'allow');
    // Late database-only deny wins over a stale seed snapshot.
    fixture.gate=async()=>{fixture.db.set('skill:catalog-fixture',row('catalog-fixture','deny'));};
    const response=await seed.POST(new Request('https://console.example.test/api/labels/seed-defaults',{method:'POST'}));
    assert.deepEqual(await response.json(),{ok:true,seeded:0,skipped:1});
    assert.equal(current('catalog-fixture').disposition,'deny');
  }else if(scenario==='sweep' || scenario==='sweep-conflict'){
    process.env.AEGIS_COLLECTOR_URL='https://collector.example.test';
    process.env.AEGIS_COLLECTOR_TOKEN='synthetic-test-value';
    globalThis.fetch=async()=>Response.json({complete:true,findings:[{device_id:'fixture-device',finding:{kind:'prompt_override',severity:'high',asset_type:'skill',asset_key:'fixture'}}]});
    if(scenario==='sweep-conflict')fixture.gate=async()=>{fixture.db.set('skill:fixture',row('fixture','monitor'));};
    else fixture.failure='before';
    const result=await remediation.runAutoRemediationSweep('fixture');
    assert.deepEqual(result.denied,[]);assert.equal(fixture.published,0);
    if(scenario==='sweep-conflict')assert.equal(current('fixture').disposition,'monitor');
    else{
      assert.equal(result.publish_blocked,'labels_write_unconfirmed');
      assert.equal(current('fixture'),undefined);assert(!JSON.stringify(fixture.audits).includes('private-'));
      fixture.failure='';const retry=await remediation.runAutoRemediationSweep('fixture');
      assert.equal(retry.denied.length,1);assert.equal(current('fixture').disposition,'deny');assert.equal(fixture.published,1);
    }
  }else if(scenario==='obsolete-load'){
    fixture.db.set('skill:fixture',row('fixture'));
    let release;fixture.load=()=>new Promise(resolve=>{release=resolve});
    const old=labels.ensureLabelsLoaded();
    fixture.failure='after';await assert.rejects(labels.removeLabel('skill','fixture'),{message:'labels_write_unconfirmed'});
    const rejected=assert.rejects(old,{message:'labels_load_failed'});release([row('fixture')]);await rejected;
    assert.deepEqual(labels.allowedAssetKeys(),new Set());
    fixture.failure='';fixture.load=async()=>[...fixture.db.values()];
    await labels.ensureLabelsLoaded();assert.deepEqual(labels.listLabels(),[]);
  }else throw new Error('unknown scenario');
  console.log('label_commit_passed:'+scenario);
})().catch(error=>{console.error(error);process.exitCode=1});
"""


class LabelCommitTests(unittest.TestCase):
    def test_real_handlers_commit_failures_and_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'boundary.cjs'
            stub.write_text(STUB)
            entry = tmp / 'entry.ts'
            entries = {'labels': 'lib/labels.ts', 'api': 'app/api/labels/route.ts',
                       'seed': 'app/api/labels/seed-defaults/route.ts', 'remediation': 'lib/auto-remediation.ts'}
            entry.write_text('\n'.join(f'export * as {name} from {json.dumps(str(ROOT / source))};' for name, source in entries.items()))
            output = tmp / 'test.cjs'
            build = r"""
const esbuild=require('esbuild');const[source,outfile,stub]=process.argv.slice(1);
esbuild.build({entryPoints:[source],outfile,bundle:true,platform:'node',format:'cjs',
 alias:Object.fromEntries(['next/server','@/lib/auth','@/lib/store','@/lib/default-allowlist','@/lib/policy','@/lib/baselines','@/lib/modules','@/lib/exempt','@/lib/rollout','@/lib/alerting'].map(x=>[x,stub])),
 plugins:[{name:'storage',setup(b){b.onResolve({filter:/^\.\/pg-store$/},()=>({path:stub}))}}]
}).catch(()=>{process.exitCode=1});
"""
            result = subprocess.run(['node', '-e', build, str(entry), str(output), str(stub)], cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in ['manual', 'lost-ack', 'delete', 'seed', 'concurrent', 'sweep', 'sweep-conflict', 'obsolete-load']:
                with self.subTest(scenario=scenario):
                    result = subprocess.run(['node', '-e', RUNNER, str(output), scenario], cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('label_commit_passed:' + scenario, result.stdout)
