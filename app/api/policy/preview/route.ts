import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { listLabels } from '@/lib/labels';
import { labelsReadyFor } from '@/lib/label-readiness';
import { getScanMode, effectiveRules, ensureBaselinesLoaded } from '@/lib/baselines';
import { computePolicyBody, listPolicyReleases, ensurePolicyReleasesLoaded, policyVersionString, enforceableRuleIds } from '@/lib/policy';
import { moduleOverrides } from '@/lib/modules';
import { exemptDevices, pinnedDevices } from '@/lib/exempt';
import { getRollout } from '@/lib/rollout';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/preview — 服务端权威计算：按当前处置注册表编译出「若现在发布」
 * 将得到的策略体（未签名）。与 publish 用同一套版本号(policyVersionString)、
 * custom_baseline_rules(enforceableRuleIds∩effectiveRules)、模块开关、exempt/pinned
 * 与灰度(rollout)设置，保证 preview==publish（此前 preview 漏传 exempt/pinned/rollout，
 * 导致 agent_self_update / enforce_exempt 与真实发布件不一致）。admin-only。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  if (!(await labelsReadyFor('policy:preview', getSession(request)?.subject ?? 'console'))) {
    return NextResponse.json({ error: 'labels_unavailable' }, { status: 503, headers: NO_STORE });
  }
  await ensurePolicyReleasesLoaded().catch(() => {});
  await ensureBaselinesLoaded().catch(() => {});
  const scanMode = getScanMode();
  const nextVersion = listPolicyReleases().reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const customRuleIds = enforceableRuleIds(effectiveRules().map((r) => r.id));
  const body = computePolicyBody({
    version: policyVersionString(nextVersion),
    scanMode,
    customRuleIds,
    modules: moduleOverrides(),
    exempt: exemptDevices(),
    pinned: pinnedDevices(),
    rollout: getRollout(),
  });
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
