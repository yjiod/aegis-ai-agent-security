import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { getDeviceStore, ensurePgHydrated } from '@/lib/store';
import { ensurePolicyReleasesLoaded, currentPolicyRelease } from '@/lib/policy';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/policy/posture — 策略生效态势（任意已认证身份可读，含审计员）。
 *
 * 回答"我发布的签名策略到底有没有真的落到终端"：把每台终端上报的 policy_version
 * 与当前生效发布件的版本对比，给出 在当前版本 / 漂移 / 未知 的分布。
 * 无发布件时返回 { published:false }（绝不伪造态势）；无终端时各计数为 0。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });

  await ensurePgHydrated().catch(() => {});
  await ensurePolicyReleasesLoaded().catch(() => {});

  const rel = currentPolicyRelease();
  const devices = [...getDeviceStore().values()];
  const total = devices.length;

  if (!rel) {
    return NextResponse.json(
      { published: false, total_devices: total, on_current: 0, drifted: 0, unknown: total },
      { headers: NO_STORE },
    );
  }

  const currentVersion = rel.policy.version;
  let onCurrent = 0;
  let drifted = 0;
  let unknown = 0;
  for (const d of devices) {
    const pv = (d.policy_version ?? '').trim();
    if (!pv) unknown += 1;
    else if (pv === currentVersion) onCurrent += 1;
    else drifted += 1;
  }

  return NextResponse.json(
    {
      published: true,
      current_version: currentVersion,
      release_version: rel.version,
      signing_key_id: rel.signing_key_id,
      total_devices: total,
      on_current: onCurrent,
      drifted,
      unknown,
      coverage: total > 0 ? Number(((onCurrent / total) * 100).toFixed(1)) : 0,
    },
    { headers: NO_STORE },
  );
}
