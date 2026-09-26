"""Execute the real sweep with isolated storage, policy and network boundaries."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = r"""
const state = () => globalThis.testState;
exports.pgEnabled = () => true;
exports.pgLoadLabels = async () => [];
exports.pgUpsertLabel = () => {};
exports.pgDeleteLabel = () => {};
exports.pgUpsertLabelsBatch = async (rows) => {
  if (state().scenario === 'save_failed') throw new Error('private-database-detail');
  return rows.length;
};
exports.getSetting = () => JSON.stringify({
  enabled: state().scenario !== 'disabled',
  auto_deny: state().scenario !== 'notify_only',
  notify: true,
});
exports.logAudit = (entry) => state().audits.push(entry);
exports.getAlertConfig = () => ({webhook: 'https://notify.example.test', format: state().format});
exports.ensurePolicyReleasesLoaded = async () => {};
exports.ensureSigningKeysLoaded = async () => {};
exports.ensureBaselinesLoaded = async () => {};
exports.publishPolicyRelease = (options) => {
  state().publications.push(options);
  return state().scenario === 'signing_missing' ? null : {version: 42};
};
exports.BLAST_CAP_ASSETS = 1;
exports.BLAST_CAP_PCT = 50;
exports.BLAST_ABS_CAP_ASSETS = 10;
exports.BLAST_ABS_CAP_PCT = 100;
exports.moduleOverrides = () => ({skill_enforce: state().scenario === 'blast_blocked', mcp_enforce: false});
exports.exemptDevices = () => [];
exports.pinnedDevices = () => [];
exports.getRollout = () => ({enabled: false, channel: 'pilot', rollout_percent: 100});
exports.getScanMode = () => 'monitor';
exports.effectiveRules = () => [];
exports.enforceableRuleIds = () => [];
"""

RUNNER = r"""
const assert = require('node:assert/strict');
const [compiled, scenario, format] = process.argv.slice(1);
const state = globalThis.testState = {scenario, format, audits: [], payloads: [], publications: []};
// Synthetic values used only by the in-process fetch stub; no network is allowed.
process.env.AEGIS_COLLECTOR_URL = 'https://collector.example.test';
process.env.AEGIS_COLLECTOR_TOKEN = 'synthetic-test-value';
if (scenario === 'unconfigured') delete process.env.AEGIS_COLLECTOR_URL;
globalThis.fetch = async (url, options) => {
  if (url.startsWith('https://collector.example.test/v1/findings/aggregate?')) {
    const findings = scenario === 'empty' ? [] : [{device_id: 'fixture-device', finding: {
      kind: 'hidden_instruction', severity: 'high', asset_type: 'skill', asset_key: 'fixture-skill',
    }}];
    return {ok: true, json: async () => ({findings, complete: true})};
  }
  if (url === 'https://collector.example.test/v1/devices?limit=500') {
    return {ok: true, json: async () => ({devices: [{device_id: 'fixture-device', skills: ['fixture-skill']}]})};
  }
  if (url === 'https://notify.example.test') {
    state.payloads.push(JSON.parse(options.body));
    if (scenario === 'notify_failed') throw new Error('synthetic delivery failure');
    return {ok: true};
  }
  throw new Error('Unexpected network request');
};
(async () => {
  const {runAutoRemediationSweep, formatRemediationSummary} = require(compiled);
  const result = await runAutoRemediationSweep('fixture-operator');
  const text = formatRemediationSummary(result);
  const inactive = ['disabled', 'unconfigured'].includes(scenario);
  const noop = ['empty', 'notify_only'].includes(scenario);
  const failed = scenario === 'save_failed';
  const blocked = failed || ['blast_blocked', 'signing_missing'].includes(scenario);
  assert.equal(result.ran, !inactive);
  assert.equal(result.status.endpoint, 'unverified');
  assert.equal(result.status.deny_rules, failed ? 'save_failed' : inactive || noop ? 'not_requested' : 'saved');
  assert.equal(result.status.policy, blocked ? 'blocked' : inactive || noop ? 'not_attempted' : 'published');
  assert.equal(result.denied.length, inactive || noop || failed ? 0 : 1);
  assert.equal(result.published_version, blocked || inactive || noop ? undefined : 42);
  assert.equal(state.publications.length, inactive || noop || failed || scenario === 'blast_blocked' ? 0 : 1);
  for (const options of state.publications) assert.equal(options.enforceOverride, false);
  assert.equal(result.notified, inactive || noop || failed || scenario === 'notify_failed' ? 0 : 1);
  assert(!JSON.stringify([result, state.audits, state.payloads]).includes('private-database-detail'));
  assert(!text.includes('自动封禁'));
  if (!inactive) assert(text.includes('终端执行未验证'));
  if (failed) assert(text.includes('规则保存失败'));
  if (blocked) assert(!text.includes('策略已发布'));
  for (const payload of state.payloads) {
    if (format === 'dingtalk') {
      assert(!payload.text.content.includes('已封禁'));
      assert(payload.text.content.includes('已保存拒绝规则'));
      assert(payload.text.content.includes('终端执行未验证'));
      if (blocked) assert(!payload.text.content.includes('策略已发布'));
    } else {
      assert.equal(payload.schema, 'aegis.remediation/v1');
      assert.deepEqual(payload.status, result.status);
      assert.deepEqual(payload.denied, result.denied);
    }
  }
  for (const audit of state.audits) {
    assert(!audit.detail.includes('自动封禁'));
    assert(audit.detail.includes('终端执行未验证'));
  }
  // A rolling deployment may still return the old body without status.
  assert(formatRemediationSummary({ran: true, denied: [{asset_key: 'fixture-skill'}], published_version: 9}).includes('终端执行未验证'));
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""


class RemediationStatusTests(unittest.TestCase):
    def test_sweep_reports_progress_without_claiming_endpoint_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            stub = tmp / 'stub.cjs'
            stub.write_text(STUB, encoding='utf-8')
            entry = tmp / 'entry.ts'
            entry.write_text(
                f'export {{ runAutoRemediationSweep }} from {json.dumps(str(ROOT / "lib/auto-remediation.ts"))};\n'
                f'export {{ formatRemediationSummary }} from {json.dumps(str(ROOT / "lib/remediation-status.ts"))};\n',
                encoding='utf-8',
            )
            compiled = tmp / 'sweep.cjs'
            # Use existing locked esbuild; never let npx download a new dependency.
            aliases = ['baselines', 'store', 'alerting', 'policy', 'modules', 'exempt', 'rollout']
            build = """
const esbuild = require('esbuild');
const [entry, output, stub, aliases] = process.argv.slice(1);
esbuild.build({entryPoints: [entry], outfile: output, bundle: true, platform: 'node', format: 'cjs',
  alias: Object.fromEntries(JSON.parse(aliases).map(name => ['@/lib/' + name, stub])),
  plugins: [{name: 'storage-boundary', setup(build) {
    build.onResolve({filter: /^\\.\\/pg-store$/}, () => ({path: stub}));
  }}],
}).catch(() => { process.exitCode = 1; });
"""
            result = subprocess.run(
                ['node', '-e', build, str(entry), str(compiled), str(stub), json.dumps(aliases)],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in ['disabled', 'unconfigured', 'empty', 'notify_only', 'save_failed',
                             'blast_blocked', 'signing_missing', 'published', 'notify_failed']:
                for format_name in ['json', 'dingtalk']:
                    with self.subTest(scenario=scenario, format=format_name):
                        result = subprocess.run(
                            ['node', '-e', RUNNER, str(compiled), scenario, format_name],
                            cwd=ROOT, capture_output=True, text=True, timeout=20,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
