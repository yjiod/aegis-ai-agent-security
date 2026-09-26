"""Labels retain their namespace across database reloads and concurrent edits."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = """
exports.pgEnabled = () => true;
exports.pgLoadLabels = () => globalThis.fixtureLoad();
exports.pgUpsertLabel = () => {};
exports.pgUpsertLabelsBatch = async rows => rows.length;
exports.pgDeleteLabel = async () => true;
"""

RUNNER = r"""
const assert = require('node:assert/strict');
const [compiled, scenario] = process.argv.slice(1);
const labels = require(compiled);
const row = (asset_type, asset_key, disposition = 'allow') => ({
  asset_type, asset_key, disposition, tags: '[]', note: '', updated_by: 'fixture-operator', updated_at: 1,
});
const edit = (asset_type, asset_key, disposition = 'deny') => labels.setLabelInMemory({
  asset_type, asset_key, disposition, updated_by: 'fixture-operator',
});
(async () => {
  if (scenario === 'types') {
    globalThis.fixtureLoad = async () => [
      row('skill', 'fixture-skill'), row('mcp', 'fixture-mcp'),
      row('path', '~/fixture/main.py'), row('prefix', '~/fixture/subdir/'),
    ];
    await labels.ensureLabelsLoaded();
    assert.deepEqual(labels.listLabels().map(x => x.asset_type).sort(), ['mcp', 'path', 'prefix', 'skill']);
    const allowed = labels.allowedAssetKeys();
    assert(!allowed.has('skill:~/fixture/main.py'));
    assert(!allowed.has('skill:~/fixture/subdir/'));
    assert(labels.isFindingAllowed({kind: 'dynamic_eval', path: '~/fixture/main.py'}, allowed));
    assert(labels.isFindingAllowed({kind: 'dynamic_eval', path: '~/fixture/subdir/child.py'}, allowed));
    assert(!labels.isFindingAllowed({kind: 'dynamic_eval', path: '~/fixture/subdir-other/child.py'}, allowed));
    assert(!labels.isFindingAllowed({asset_type: 'skill', asset_key: '~/fixture/subdir/child.py'}, allowed));
  } else if (scenario === 'unavailable' || scenario === 'exception' || scenario === 'invalid') {
    let calls = 0;
    globalThis.fixtureLoad = async () => {
      calls++;
      if (calls > 1) return [row('path', '~/fixture/retry.py')];
      if (scenario === 'exception') throw new Error('private-storage-details');
      if (scenario === 'invalid') return [row('skill', 'partial'), row('future-type', 'unknown')];
      return null;
    };
    edit('mcp', 'existing');
    await assert.rejects(labels.ensureLabelsLoaded(), {message: 'labels_load_failed'});
    assert.deepEqual(labels.listLabels().map(x => x.asset_key), ['existing']);
    await labels.ensureLabelsLoaded();
    assert.equal(calls, 2);
    assert(labels.allowedAssetKeys().has('path:~/fixture/retry.py'));
    await labels.ensureLabelsLoaded();
    assert.equal(calls, 2);
  } else if (scenario === 'concurrent') {
    let resolve;
    let calls = 0;
    globalThis.fixtureLoad = () => { calls++; return new Promise(done => { resolve = done; }); };
    edit('skill', 'deleted');
    const first = labels.ensureLabelsLoaded();
    const second = labels.ensureLabelsLoaded();
    edit('skill', 'changed', 'monitor');
    await labels.removeLabel('skill', 'deleted');
    // Deletion must also protect a database row absent from the initial memory.
    await labels.removeLabel('mcp', 'not-yet-loaded');
    edit('path', '~/fixture/transient.py');
    await labels.removeLabel('path', '~/fixture/transient.py');
    resolve([
      row('skill', 'changed'), row('skill', 'deleted'), row('mcp', 'not-yet-loaded'),
      row('path', '~/fixture/transient.py'), row('mcp', 'untouched'),
    ]);
    await Promise.all([first, second]);
    assert.equal(calls, 1);
    assert.deepEqual(labels.listLabels().map(x => [x.asset_key, x.disposition]), [
      ['untouched', 'allow'], ['changed', 'monitor'],
    ]);
  } else if (scenario === 'empty') {
    let calls = 0;
    globalThis.fixtureLoad = async () => { calls++; return []; };
    await labels.ensureLabelsLoaded();
    await labels.ensureLabelsLoaded();
    assert.equal(calls, 1);
    assert.deepEqual(labels.listLabels(), []);
  } else throw new Error('unknown fixture scenario');
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


class LabelHydrationTests(unittest.TestCase):
    def test_hydration_types_failures_and_concurrent_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'storage.cjs'
            stub.write_text(STUB, encoding='utf-8')
            compiled = tmp / 'labels.cjs'
            build = r"""
const esbuild = require('esbuild');
const [source, output, stub] = process.argv.slice(1);
esbuild.build({entryPoints: [source], outfile: output, bundle: true, platform: 'node', format: 'cjs',
  plugins: [{name: 'storage-boundary', setup(build) {
    build.onResolve({filter: /^\.\/pg-store$/}, () => ({path: stub}));
  }}],
}).catch(() => { process.exitCode = 1; });
"""
            result = subprocess.run(
                ['node', '-e', build, str(ROOT / 'lib/labels.ts'), str(compiled), str(stub)],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in ['types', 'unavailable', 'exception', 'invalid', 'concurrent', 'empty']:
                with self.subTest(scenario=scenario):
                    result = subprocess.run(
                        ['node', '-e', RUNNER, str(compiled), scenario],
                        cwd=ROOT, capture_output=True, text=True, timeout=20,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
