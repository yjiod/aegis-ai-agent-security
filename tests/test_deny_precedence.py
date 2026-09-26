"""Deny rules must win over exact, ancestor and stale allow decisions."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = r"""
exports.NextResponse = {json: (body, options = {}) => new Response(JSON.stringify(body), options)};
exports.getSession = () => globalThis.authenticated ? {subject: 'fixture-admin'} : null;
exports.requireAdmin = () => globalThis.authenticated ? null : new Response('{}', {status: 401});
exports.logAudit = entry => globalThis.audits.push(entry);
exports.pgEnabled = () => false;
exports.pgUpsertLabel = () => {};
exports.pgDeleteLabel = () => {};
"""

RUNNER = r"""
const assert = require('node:assert/strict');
const {labels, route} = require(process.argv[1]);
globalThis.authenticated = true;
globalThis.audits = [];
function set(type, key, disposition) {
  labels.setLabelInMemory({asset_type: type, asset_key: key, disposition, updated_by: 'fixture-admin'});
}
const finding = {kind: 'hardcoded_secret', path: '~/project/nested/main.py'};
set('prefix', '~/project/', 'allow');
assert.equal(labels.isFindingAllowed(finding, labels.allowedAssetKeys()), true);
// An exact deny wins over an ancestor allow.
set('path', '~/project/nested/main.py', 'deny');
assert.equal(labels.isFindingAllowed(finding, labels.allowedAssetKeys()), false);
labels.removeLabel('path', '~/project/nested/main.py');
assert.equal(labels.isFindingAllowed(finding, labels.allowedAssetKeys()), true);
// An ancestor deny wins over a deeper allow and an exact allow.
set('prefix', '~/project/', 'deny');
set('prefix', '~/project/nested/', 'allow');
set('path', '~/project/nested/main.py', 'allow');
assert.equal(labels.isFindingAllowed(finding, labels.allowedAssetKeys()), false);
// A deeper deny also wins over an outer allow.
set('prefix', '~/project/', 'allow');
set('prefix', '~/project/nested/', 'deny');
assert.equal(labels.isFindingAllowed(finding, labels.allowedAssetKeys()), false);
// A sibling directory does not inherit the nested deny.
assert.equal(labels.isFindingAllowed({...finding, path: '~/project/nested-other/main.py'}, labels.allowedAssetKeys()), true);
// Line/column suffixes and event IDs do not invalidate a path's deny match.
assert.equal(labels.isFindingAllowed({...finding, event_id: 'different', path: '~/project/nested/main.py:24:9'}, labels.allowedAssetKeys()), false);
for (const type of ['skill', 'mcp', 'path']) {
  const key = type === 'path' ? '~/other/main.py' : 'fixture-asset';
  const f = type === 'path' ? {...finding, path: key} : {kind: 'unknown_' + type, asset_type: type, asset_key: key};
  set(type, key, 'allow');
  const stale = labels.allowedAssetKeys();
  assert.equal(labels.isFindingAllowed(f, stale), true);
  set(type, key, 'deny');
  assert.equal(labels.isFindingAllowed(f, stale), false);
}
// A code prefix cannot silently govern an explicitly identified skill/MCP.
set('skill', 'fixture-isolated', 'allow');
assert.equal(labels.isFindingAllowed({asset_type: 'skill', asset_key: 'fixture-isolated', path: '~/project/nested/SKILL.md'}, labels.allowedAssetKeys()), true);
assert.equal(labels.isFindingAllowed({kind: 'unreadable', path: '~/project/nested/main.py'}, labels.allowedAssetKeys()), false);

function request(body) {
  return new Request('https://console.example.test/api/labels', {method: 'POST', body: JSON.stringify(body)});
}
(async () => {
  // Exercise the real API handler: valid prefix rules must pass the name check.
  for (const disposition of ['allow', 'deny']) {
    const response = await route.POST(request({asset_type: 'prefix', asset_key: '~/Fixture/API/', disposition}));
    assert.equal(response.status, 200);
    assert.equal((await response.json()).label.asset_key, '~/fixture/api/');
  }
  assert.equal(labels.isFindingAllowed({...finding, path: '~/fixture/api/main.py'}, new Set(['prefix:~/fixture/'])), false);
  assert.equal(audits.length, 2);
  for (const asset_key of ['~/', '/', '~/fixture/no-slash']) {
    assert.equal((await route.POST(request({asset_type: 'prefix', asset_key, disposition: 'allow'}))).status, 400);
  }
  for (const asset_type of ['skill', 'mcp']) {
    assert.equal((await route.POST(request({asset_type, asset_key: '~/fixture/name', disposition: 'allow'}))).status, 400);
  }
  globalThis.authenticated = false;
  assert.equal((await route.POST(request({asset_type: 'prefix', asset_key: '~/fixture/api/', disposition: 'allow'}))).status, 401);
  assert.equal(audits.length, 2);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


class DenyPrecedenceTests(unittest.TestCase):
    def test_filter_and_real_prefix_route(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'boundary.cjs'
            stub.write_text(STUB)
            entry = tmp / 'entry.ts'
            entry.write_text('\n'.join([
                'export * as labels from ' + json.dumps(str(ROOT / 'lib/labels.ts')) + ';',
                'export * as route from ' + json.dumps(str(ROOT / 'app/api/labels/route.ts')) + ';',
            ]))
            compiled = tmp / 'test.cjs'
            build = r"""
const esbuild = require('esbuild');
const [source, output, stub] = process.argv.slice(1);
esbuild.build({entryPoints: [source], outfile: output, bundle: true, platform: 'node', format: 'cjs',
  alias: {'next/server': stub, '@/lib/auth': stub, '@/lib/store': stub},
  plugins: [{name: 'storage', setup(build) {
    build.onResolve({filter: /^\.\/pg-store$/}, () => ({path: stub}));
  }}],
}).catch(() => { process.exitCode = 1; });
"""
            for args in [
                ['node', '-e', build, str(entry), str(compiled), str(stub)],
                ['node', '-e', RUNNER, str(compiled)],
            ]:
                result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
