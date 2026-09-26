/* Isolated PostgreSQL contract test. Requires the caller's disposable local socket. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';
const { Client } = pg;
import * as esbuild from 'esbuild';

async function main() {
  const [socket, port] = process.argv.slice(2);
  assert(socket && path.isAbsolute(socket) && /^\d{4,5}$/.test(port), 'fixture_socket_required');
  const stat = await fs.stat(socket);
  assert(stat.isDirectory(), 'fixture_socket_required');
  const config = { host: socket, port: Number(port), user: 'aegis_fixture', database: 'postgres' };
  const admin = new Client(config);
  await admin.connect();
  // Fixed synthetic database in the caller-created disposable cluster only.
  await admin.query('CREATE DATABASE aegis_label_fixture');
  await admin.end();
  const client = new Client({ ...config, database: 'aegis_label_fixture' });
  await client.connect();
  try {
    await client.query(await fs.readFile('migrations/0003_asset_labels.sql', 'utf8'));
    await client.query('INSERT INTO asset_labels(asset_type,asset_key,disposition,tags) VALUES($1,$2,$3,$4)',
      ['skill','historical-fixture','allow','["default-bundled"]']);
    const migration = await fs.readFile('migrations/0008_label_decision_source.sql', 'utf8');
    await client.query(migration);
    await client.query(migration); // repeatable deployment
    const legacy = await client.query('SELECT decision_source FROM asset_labels WHERE asset_key=$1', ['historical-fixture']);
    assert.equal(legacy.rows[0].decision_source, 'legacy');
    await assert.rejects(client.query('UPDATE asset_labels SET decision_source=$1', ['forged']), { code: '23514' });

    const boundary = path.join(socket, 'after.cjs');
    await fs.writeFile(boundary, 'exports.after = task => globalThis.aegisFixtureWrites.push(task());\n');
    const output = path.join(socket, 'pg-store.cjs');
    await esbuild.build({ entryPoints: ['lib/pg-store.ts'], outfile: output, bundle: true,
      platform: 'node', format: 'cjs', alias: { 'next/server': boundary },
      // Resolve the already locked driver; no dependency install or dynamic network.
      plugins: [{ name: 'driver', setup(build) {
        build.onResolve({ filter: /^pg$/ }, () => ({ path: fileURLToPath(import.meta.resolve('pg')), external: true }));
      } }],
    });
    process.env.AEGIS_PG_URL = 'postgresql://aegis_fixture@localhost/aegis_label_fixture?host=' + encodeURIComponent(socket) + '&port=' + port;
    globalThis.aegisFixtureWrites = [];
    const store = (await import(pathToFileURL(output).href)).default;
    const row = (key, source) => ({ asset_type:'skill', asset_key:key, disposition:'allow', tags:'[]',
      note:'synthetic', updated_by:'fixture', updated_at:1, decision_source:source });
    await store.pgUpsertLabel(row('manual-fixture','manual'));
    assert.equal(await store.pgUpsertLabelsBatch([row('preset-fixture','preset'),row('auto-fixture','automatic')]),2);
    let loaded = await store.pgLoadLabels();
    assert.deepEqual(Object.fromEntries(loaded.map(r => [r.asset_key,r.decision_source])), {
      'historical-fixture':'legacy','manual-fixture':'manual','preset-fixture':'preset','auto-fixture':'automatic',
    });
    await store.pgUpsertLabelsBatch([row('preset-fixture','manual')]);
    loaded = await store.pgLoadLabels();
    assert.equal(loaded.find(r=>r.asset_key==='preset-fixture').decision_source,'manual');
    // An invalid source rolls back the entire batch, including earlier rows.
    await assert.rejects(store.pgUpsertLabelsBatch([row('rollback-fixture','preset'),row('invalid-fixture','forged')]));
    loaded = await store.pgLoadLabels();
    assert(!loaded.some(r=>r.asset_key==='rollback-fixture' || r.asset_key==='invalid-fixture'));
    await store.pgApplyLabelChanges([{...row('deny-fixture','manual'), disposition:'deny'}]);
    const skipped = await store.pgApplyLabelChanges([row('deny-fixture','preset')], true);
    assert.deepEqual(skipped.appliedKeys, []);
    assert.equal(skipped.labels[0].disposition, 'deny');
    await store.pgApplyLabelChanges([{asset_type:'skill',asset_key:'deny-fixture',note:'new annotation',updated_by:'fixture',updated_at:2}]);
    loaded=await store.pgLoadLabels();
    assert.equal(loaded.find(r=>r.asset_key==='deny-fixture').disposition,'deny');
    assert.equal(loaded.find(r=>r.asset_key==='deny-fixture').decision_source,'manual');
    // Two independent connections: neither insertion order may erase the deny.
    await Promise.all([
      store.pgApplyLabelChanges([row('race-fixture','preset')],true),
      store.pgApplyLabelChanges([{...row('race-fixture','manual'),disposition:'deny'}]),
    ]);
    assert.equal((await store.pgLoadLabels()).find(r=>r.asset_key==='race-fixture').disposition,'deny');
    assert.equal(await store.pgDeleteLabel('skill','race-fixture'),true);
    assert.equal(await store.pgDeleteLabel('skill','race-fixture'),false);
    console.log('label_postgres_passed:migration=repeatable:legacy=preserved:sources=roundtrip:invalid_batch=rollback:patch=preserved:conditional=deny_wins:delete=confirmed');
  } finally {
    await client.end();
  }
}
main().catch(() => { console.error('label_postgres_fixture_failed'); process.exitCode = 1; });
