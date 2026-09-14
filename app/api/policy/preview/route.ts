import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { ensureLabelsLoaded, listLabels } from '@/lib/labels';
import { getScanMode } from '@/lib/baselines';
import { computePolicyBody, listPolicyReleases } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/preview — 服务端权威计算：按当前处置注册表编译出「若现在发布」
 * 将得到的策略体（未签名）。把此前只在客户端做的预览上移为权威计算，保证
 * preview 输出与 publish 输出一致。admin-only。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  await ensureLabelsLoaded().catch(() => {});
  const scanMode = getScanMode();
  const nextVersion = listPolicyReleases().reduce((max, r) => Math.max(max, r.version), 0) + 1;
  const body = computePolicyBody({ version: `${nextVersion}.0.0`, scanMode });
  const labels = listLabels();
  return NextResponse.json(
    {
      next_version: nextVersion,
      scan_mode: scanMode,
      policy: body,
      counts: {
        allow: labels.filter((l) => l.disposition === 'allow').length,
        monitor: labels.filter((l) => l.disposition === 'monitor').length,
        deny: labels.filter((l) => l.disposition === 'deny').length,
      },
    },
    { headers: NO_STORE },
  );
}
