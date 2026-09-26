"""An unavailable label snapshot blocks actual mutation and publish handlers."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = r"""
const state = () => globalThis.fixture;
exports.NextResponse = {json: (body, options = {}) => new Response(JSON.stringify(body), options)};
exports.getSession = () => state().authenticated ? {subject: 'fixture-operator'} : null;
exports.requireAdmin = () => state().authenticated ? null : new Response('{}', {status: 401});
exports.logAudit = entry => state().audits.push(entry);
exports.getSetting = () => null;
exports.pgEnabled = () => true;
exports.pgLoadLabels = async () => {
  state().loads++;
  if (state().recovered) return [{asset_type: 'path', asset_key: '~/fixture/main.py', disposition: 'allow', tags: '[]'}];
  if (state().failure === 'null') return null;
  if (state().failure === 'exception') throw new Error('private-database-detail');
  return [{asset_type: 'invalid-type', asset_key: 'fixture-invalid'}];
};
for (const name of [
  'pgUpsertLabel', 'pgUpsertLabelsBatch', 'pgDeleteLabel', 'getAlertConfig',
  'ensurePolicyReleasesLoaded', 'ensureSigningKeysLoaded', 'publishPolicyRelease',
  'defaultBundledEntries', 'ensureBaselinesLoaded', 'recordPipelineEvent',
]) exports[name] = () => { state().effects++; throw new Error('Unexpected side effect: ' + name); };
"""

RUNNER = r"""
const assert = require('node:assert/strict');
const [compiled, failure] = process.argv.slice(1);
globalThis.fixture = {authenticated: true, failure, recovered: false, loads: 0, effects: 0, audits: []};
process.env.AEGIS_COLLECTOR_URL = 'https://collector.example.test';
process.env.AEGIS_COLLECTOR_TOKEN = 'synthetic-test-value';
globalThis.fetch = () => { fixture.effects++; throw new Error('Network must not be used'); };
const {labels, seed, preview, publish, sweep} = require(compiled);
const cases = [
  [labels.GET, 'GET', '/labels'],
  [labels.POST, 'POST', '/labels', {asset_type: 'mcp', asset_key: 'fixture-mcp', disposition: 'deny'}],
  [labels.DELETE, 'DELETE', '/labels?asset_type=mcp&asset_key=fixture-mcp'],
  [seed.POST, 'POST', '/labels/seed-defaults', {}],
  [preview.GET, 'GET', '/policy/preview'],
  [publish.POST, 'POST', '/policy/publish', {}],
  [sweep.POST, 'POST', '/remediation/auto-sweep', {}],
];
function request(method, path, body) {
  return new Request('https://console.example.test/api' + path, {
    method, ...(body ? {body: JSON.stringify(body), headers: {'Content-Type': 'application/json'}} : {}),
  });
}
(async () => {
  for (const [handler, method, path, body] of cases) {
    const response = await handler(request(method, path, body));
    assert.equal(response.status, 503, path);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    const output = await response.json();
    assert.equal(output.error ?? output.reason, 'labels_unavailable');
    assert(!JSON.stringify(output).includes('private-database-detail'));
    if (handler === sweep.POST) {
      assert.equal(output.ran, false);
      assert.deepEqual(output.denied, []);
      assert.equal(output.published_version, undefined);
    }
  }
  assert.equal(fixture.effects, 0);
  assert.equal(fixture.loads, cases.length);
  assert.equal(fixture.audits.length, cases.length);
  assert(fixture.audits.every(x => x.action === 'labels:load_failed'));
  assert(!JSON.stringify(fixture.audits).includes('private-database-detail'));
  // Authorization must still precede loading, including during a storage outage.
  fixture.authenticated = false;
  for (const [handler, method, path, body] of cases) {
    assert.equal((await handler(request(method, path, body))).status, 401);
  }
  assert.equal(fixture.loads, cases.length);
  fixture.authenticated = true;
  fixture.recovered = true;
  const restored = await labels.GET(request('GET', '/labels'));
  assert.equal(restored.status, 200);
  assert.equal((await restored.json()).labels[0].asset_type, 'path');
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


class LabelReadinessTests(unittest.TestCase):
    def test_unavailable_labels_block_handlers_and_recover(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'boundary.cjs'
            stub.write_text(STUB, encoding='utf-8')
            entries = {
                'labels': 'app/api/labels/route.ts',
                'seed': 'app/api/labels/seed-defaults/route.ts',
                'preview': 'app/api/policy/preview/route.ts',
                'publish': 'app/api/policy/publish/route.ts',
                'sweep': 'app/api/remediation/auto-sweep/route.ts',
            }
            entry = tmp / 'entry.ts'
            entry.write_text('\n'.join(
                f'export * as {name} from {json.dumps(str(ROOT / path))};'
                for name, path in entries.items()
            ), encoding='utf-8')
            compiled = tmp / 'handlers.cjs'
            aliases = ['auth', 'store', 'baselines', 'policy', 'modules', 'exempt', 'rollout',
                       'pipeline-telemetry', 'default-allowlist', 'alerting']
            build = r"""
const esbuild = require('esbuild');
const [source, output, stub, aliases] = process.argv.slice(1);
esbuild.build({entryPoints: [source], outfile: output, bundle: true, platform: 'node', format: 'cjs',
  alias: {...Object.fromEntries(JSON.parse(aliases).map(name => ['@/lib/' + name, stub])), 'next/server': stub},
  plugins: [{name: 'storage-boundary', setup(build) {
    build.onResolve({filter: /^\.\/pg-store$/}, () => ({path: stub}));
  }}],
}).catch(() => { process.exitCode = 1; });
"""
            result = subprocess.run(
                ['node', '-e', build, str(entry), str(compiled), str(stub), json.dumps(aliases)],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for failure in ['null', 'exception', 'invalid']:
                with self.subTest(failure=failure):
                    result = subprocess.run(
                        ['node', '-e', RUNNER, str(compiled), failure],
                        cwd=ROOT, capture_output=True, text=True, timeout=20,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
