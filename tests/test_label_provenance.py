"""Catalog admission must not hide behavioral risk or impersonate manual decisions."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = r"""
exports.NextResponse = {json: (body, options = {}) => new Response(JSON.stringify(body), options)};
exports.getSession = () => fixture.auth ? {subject: 'fixture-admin'} : null;
exports.requireAdmin = exports.requireSession = () => fixture.auth ? null : new Response('{}', {status: 401});
exports.logAudit = entry => fixture.audits.push(entry);
exports.pgEnabled = () => true;
exports.pgLoadLabels = async () => fixture.rows;
exports.pgUpsertLabel = row => fixture.writes.push(row);
exports.pgApplyLabelChanges = async (patches,onlyUndecided) => {
  const labels=[],appliedKeys=[];
  for(const patch of patches){
    const prev=fixture.rows.find(r=>r.asset_type===patch.asset_type && r.asset_key===patch.asset_key);
    if(onlyUndecided && prev?.disposition){labels.push(prev);continue;}
    const row={tags:'[]',disposition:'',note:'',...prev,...Object.fromEntries(Object.entries(patch).filter(([,v])=>v!==undefined)),
      decision_source:patch.disposition!==undefined ? (patch.decision_source??'manual') : (prev?.decision_source??'legacy')};
    labels.push(row);appliedKeys.push(row.asset_type+':'+row.asset_key);fixture.writes.push(row);
    fixture.rows=fixture.rows.filter(r=>r.asset_type!==row.asset_type || r.asset_key!==row.asset_key);fixture.rows.push(row);
  }
  return {labels,appliedKeys};
};
exports.pgDeleteLabel = () => {};
exports.defaultBundledEntries = () => [{asset_type:'skill',asset_key:'catalog-entry'}, {asset_type:'mcp',asset_key:'denied-entry'}];
exports.BASE_POLICY = {skill_rules:['unknown_skill','prompt_override'],mcp_rules:['unknown_mcp'],code_rules:[]};
exports.ensurePgHydrated = async () => {};
exports.getTicketStore = () => fixture.tickets;
exports.getDeviceStore = () => new Map();
exports.nextTicketId = () => 'fixture-ticket';
exports.TICKET_SEVERITIES = ['critical','high','medium','low'];
exports.TICKET_STATUSES = ['open','resolved','dismissed'];
exports.getSetting = () => null;
"""

RUNNER = r"""
const assert = require('node:assert/strict');
const [compiled, scenario] = process.argv.slice(1);
globalThis.fixture = {auth:true,rows:[],writes:[],audits:[],tickets:new Map()};
const {labels, api, seed, findings, device, tickets, remediation, openapi} = require(compiled);
const make = (key, source, type='skill') => ({asset_type:type,asset_key:key,disposition:'allow',
  decision_source:source,tags:'["default-bundled"]',note:'',updated_by:'fixture-admin',updated_at:1});
const f = (key, kind='prompt_override', type='skill') => ({asset_type:type,asset_key:key,kind,severity:'high',path:'~/fixture/SKILL.md'});
const allowed = finding => labels.isFindingAllowed(finding, labels.allowedAssetKeys());
const post = body => api.POST(new Request('https://console.example.test/api/labels', {method:'POST',body:JSON.stringify(body)}));
(async () => {
  if (scenario === 'invalid-source') {
    fixture.rows = [make('first','manual'),make('invalid','forged')];
    await assert.rejects(labels.ensureLabelsLoaded(), {message:'labels_load_failed'});
    assert.deepEqual(labels.listLabels(), []);
    fixture.rows = [make('recovered','preset')];
    await labels.ensureLabelsLoaded();
    assert.equal(allowed(f('recovered')), false);
    return;
  }
  for (const source of ['manual','preset','automatic','legacy',undefined]) {
    for (const type of ['skill','mcp']) fixture.rows.push(make(type+'-'+source,source,type));
  }
  await labels.ensureLabelsLoaded();
  for (const source of ['manual','preset','automatic','legacy',undefined]) {
    for (const type of ['skill','mcp']) {
      const key=type+'-'+source;
      assert.equal(allowed(f(key,type==='skill'?'prompt_override':'mcp_url_credentials',type)), source==='manual');
      assert.equal(allowed(f(key,'unknown_'+type,type)), true);
      assert.equal(allowed(f(key,undefined,type)), source==='manual');
    }
  }
  // Editable tags and matching catalog names never elevate historical provenance.
  assert.equal(labels.listLabels().find(l=>l.asset_key==='skill-undefined').decision_source,'legacy');
  if (scenario === 'writers') {
    const contract=openapi.openApiDoc().paths['/labels'];
    assert.equal(contract.post['x-access'],'admin');
    assert.deepEqual(contract.post.requestBody.content['application/json'].schema.not,{required:['decision_source']});
    const responseSchema=contract.get.responses['200'].content['application/json'].schema.properties.labels.items;
    const listing=await (await api.GET(new Request('https://console.example.test/api/labels'))).json();
    for(const row of listing.labels){
      assert(responseSchema.required.every(key=>Object.hasOwn(row,key)));
      assert(responseSchema.properties.decision_source.enum.includes(row.decision_source));
    }
    const key='skill-preset';
    for (const patch of [{tags:['edited']},{note:'annotation only'}]) {
      const r=await post({asset_type:'skill',asset_key:key,...patch});
      assert.equal(r.status,200);
      assert.equal((await r.json()).label.decision_source,'preset');
      assert.equal(allowed(f(key)),false);
    }
    for (const source of ['manual','preset','automatic','legacy',null]) {
      const r=await post({asset_type:'skill',asset_key:key,decision_source:source});
      assert.equal(r.status,400);
      assert.equal((await r.json()).error,'decision_source_read_only');
    }
    for (const body of [null,[],1]) assert.equal((await post(body)).status,400);
    fixture.auth=false;
    assert.equal((await post({decision_source:'manual'})).status,401);
    fixture.auth=true;
    const before=labels.allowedAssetKeys();
    let r=await post({asset_type:'skill',asset_key:key,disposition:'deny'});
    assert.equal((await r.json()).label.decision_source,'manual');
    assert.equal(labels.isFindingAllowed(f(key,'unknown_skill'),before),false);
    r=await post({asset_type:'skill',asset_key:key,disposition:'allow'});
    assert.equal((await r.json()).label.decision_source,'manual');
    assert.equal(allowed(f(key)),true);
    assert(fixture.writes.some(row=>row.asset_key===key && row.decision_source==='manual'));
    await labels.setLabel({asset_type:'mcp',asset_key:'denied-entry',disposition:'deny',updated_by:'fixture-admin'});
    r=await seed.POST(new Request('https://console.example.test/api/labels/seed-defaults',{method:'POST'}));
    assert.equal(r.status,200);
    assert.deepEqual(await r.json(),{ok:true,seeded:1,skipped:1});
    assert.equal(labels.listLabels().find(l=>l.asset_key==='catalog-entry').decision_source,'preset');
    assert(fixture.writes.some(row=>row.asset_key==='catalog-entry' && row.decision_source==='preset'));
    assert.equal(allowed(f('catalog-entry')),false);
    r=await seed.POST(new Request('https://console.example.test/api/labels/seed-defaults',{method:'POST'}));
    assert.deepEqual(await r.json(),{ok:true,seeded:0,skipped:2});
    assert.equal(labels.listLabels().find(l=>l.asset_key==='denied-entry').disposition,'deny');
    const decision=remediation.decideRemediation([f('catalog-entry')],labels.listLabels());
    assert.equal(decision.conflicts[0].decision_source,'preset');
    assert.equal(decision.denies.length,0); // provenance alone does not increase confidence
    return;
  }
  if (scenario !== 'consumers') throw new Error('unknown scenario');
  process.env.AEGIS_COLLECTOR_URL='https://collector.example.test';
  process.env.AEGIS_COLLECTOR_TOKEN='synthetic-test-value';
  const reports=[f('skill-preset','unknown_skill'),f('skill-preset')];
  globalThis.fetch=async input=>{
    const url=new URL(input);
    assert.equal(url.origin,'https://collector.example.test');
    if(url.pathname==='/v1/findings/aggregate')return Response.json({devices_scanned:1,complete:true,findings:reports.map(finding=>({device_id:'fixture-device',scanned_at:1,finding}))});
    if(url.pathname==='/v1/findings')return Response.json({findings:reports});
    if(url.pathname==='/v1/devices')return Response.json({complete:true,devices:[{device_id:'fixture-device',latest_severity:{high:2}}]});
    throw new Error('unexpected fixture URL');
  };
  let r=await findings.GET(new Request('https://console.example.test/api/findings'));
  let body=await r.json();
  assert.equal(r.status,200);assert.equal(body.suppressed,1);
  assert.deepEqual(body.findings.map(f=>f.kind),['prompt_override']);
  r=await device.GET(new Request('https://console.example.test/api/devices/fixture-device/findings'),{params:Promise.resolve({id:'fixture-device'})});
  body=await r.json();assert.equal(body.suppressed,1);
  assert.deepEqual(body.findings.map(f=>f.kind),['prompt_override']);
  r=await tickets.GET(new Request('https://console.example.test/api/tickets'));
  assert.equal(r.status,200);
  assert.equal(fixture.tickets.size,1);
  assert.equal(fixture.tickets.get('fixture-ticket').status,'open');
  // Subsequent reads cannot auto-resolve an existing risk ticket on preset allow.
  const now=Date.now;Date.now=()=>now()+61000;
  r=await tickets.GET(new Request('https://console.example.test/api/tickets'));
  assert.equal(r.status,200);assert.equal(fixture.tickets.get('fixture-ticket').status,'open');
  Date.now=now;
  fixture.auth=false;
  assert.equal((await findings.GET(new Request('https://console.example.test/api/findings'))).status,401);
})().catch(error=>{console.error(error);process.exitCode=1});
"""


class LabelProvenanceTests(unittest.TestCase):
    def test_sources_writers_and_actual_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'boundary.cjs'
            stub.write_text(STUB)
            entries = {
                'labels': 'lib/labels.ts', 'api': 'app/api/labels/route.ts',
                'seed': 'app/api/labels/seed-defaults/route.ts',
                'findings': 'app/api/findings/route.ts',
                'device': 'app/api/devices/[id]/findings/route.ts',
                'tickets': 'app/api/tickets/route.ts', 'remediation': 'lib/auto-remediation.ts',
                'openapi': 'lib/openapi.ts',
            }
            entry = tmp / 'entry.ts'
            entry.write_text('\n'.join(f'export * as {name} from {json.dumps(str(ROOT / path))};' for name, path in entries.items()))
            output = tmp / 'test.cjs'
            build = r"""
const esbuild=require('esbuild');
const [source,outfile,stub]=process.argv.slice(1);
esbuild.build({entryPoints:[source],outfile,bundle:true,platform:'node',format:'cjs',
 alias:Object.fromEntries(['next/server','@/lib/auth','@/lib/store','@/lib/default-allowlist','@/lib/policy','@/lib/baselines'].map(x=>[x,stub])),
 plugins:[{name:'storage',setup(b){b.onResolve({filter:/^\.\/pg-store$/},()=>({path:stub}))}}]
}).catch(()=>{process.exitCode=1});
"""
            result = subprocess.run(['node', '-e', build, str(entry), str(output), str(stub)], cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in ['writers', 'consumers', 'invalid-source']:
                with self.subTest(scenario=scenario):
                    result = subprocess.run(['node', '-e', RUNNER, str(output), scenario], cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_postgres_adapter_preserves_source_in_single_and_batch_writes(self):
        # Runs the real SQL adapter against an isolated client boundary. This is
        # not an executed PostgreSQL migration or a production durability test.
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'pg.cjs'
            stub.write_text(r"""
exports.after = task => globalThis.pending.push(task());
exports.Client = class {
  async connect() {}
  async end() {}
  async query(sql, args) {
    if (sql.startsWith('INSERT INTO asset_labels')) {
      const columns = sql.match(/asset_labels\(([^)]+)\)/)[1].split(',');
      const row = Object.fromEntries(columns.map((name, i) => [name, args[i]]));
      row.decision_source ??= row.disposition == null ? 'legacy' : 'manual';
      globalThis.rows.set(row.asset_key, row);
      return {rows:[row]};
    }
    if (sql.startsWith('SELECT')) {
      const columns = sql.slice('SELECT '.length, sql.indexOf(' FROM')).split(',');
      return {rows:[...globalThis.rows.values()].map(row => Object.fromEntries(columns.map(name => [name,row[name]])))};
    }
    return {rows:[]};
  }
};
""")
            output = tmp / 'pg-store.cjs'
            build = r"""
const esbuild=require('esbuild');
const [source,outfile,stub]=process.argv.slice(1);
esbuild.build({entryPoints:[source],outfile,bundle:true,platform:'node',format:'cjs',alias:{'pg':stub,'next/server':stub}}).catch(()=>{process.exitCode=1});
"""
            run = r"""
const assert=require('node:assert/strict');
globalThis.rows=new Map();globalThis.pending=[];
process.env.AEGIS_PG_URL='postgresql://fixture.example.test/synthetic';
const pg=require(process.argv[1]);
const row=(key,source)=>({asset_type:'skill',asset_key:key,tags:'[]',disposition:'allow',note:'',updated_by:'fixture',updated_at:1,decision_source:source});
(async()=>{
  await pg.pgUpsertLabel(row('single','manual'));
  assert.equal(await pg.pgUpsertLabelsBatch([row('preset','preset'),row('auto','automatic'),row('old',undefined)]),3);
  const loaded=await pg.pgLoadLabels();
  assert.deepEqual(Object.fromEntries(loaded.map(r=>[r.asset_key,r.decision_source])),{single:'manual',preset:'preset',auto:'automatic',old:'manual'});
})().catch(error=>{console.error(error);process.exitCode=1});
"""
            for args in [['node', '-e', build, str(ROOT / 'lib/pg-store.ts'), str(output), str(stub)],
                         ['node', '-e', run, str(output)]]:
                result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
