import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { ensureLabelsLoaded, listLabels } from '@/lib/labels';
import { getScanMode, effectiveRules, ensureBaselinesLoaded } from '@/lib/baselines';
import { computePolicyBody, listPolicyReleases, ensurePolicyReleasesLoaded, policyVersionString, enforceableRuleIds } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/preview — 服务端权威计算：按当前处置注册表编译出「若现在发布」
 * 将得到的策略体（未签名）。与 publish 用同一套版本号(policyVersionString)与
 * custom_baseline_rules(enforceableRuleIds∩effectiveRules)，保证 preview==publish。admin-only。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  await ensureLabelsLoaded().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureBaselinesLoaded().catch(() => {});
  const scanMode = getScanMode();
  const nextVersion = listPolicyReleases().reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const customRuleIds = enforceableRuleIds(effectiveRules().map((r) => r.id));
  const body = computePolicyBody({ version: policyVersionString(nextVersion), scanMode, customRuleIds });
  const labels = listLabels();
  return NextResponse.json(
    {
      next_version: nextVersion,
      scan_mode: scanMode,
      policy: body,
      enforceable_custom_rules: customRuleIds.length,
      custom_mode_blocked: scanMode === 'custom' && customRuleIds.length === 0,
      counts: {
        allow: labels.filter((l) => l.disposition === 'allow').length,
        monitor: labels.filter((l) => l.disposition === 'monitor').length,
        deny: labels.filter((l) => l.disposition === 'deny').length,
      },
    },
    { headers: NO_STORE },
  );
}
