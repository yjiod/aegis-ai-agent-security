/**
 * app/api/settings/rollout/route.ts — Agent 自更新灰度（canary）设置。
 *
 * GET  /api/settings/rollout -> 当前灰度配置（登录即可，供分发中心页展示）。
 * PUT  /api/settings/rollout -> 设置 { enabled, channel, rollout_percent }（admin）。
 *
 * 与 exempt/pinned 同一套 settings 机制；改动在**下次发布策略**时注入 agent_self_update
 * 并对终端生效（终端按 device_id 稳定哈希分桶，桶号 < rollout_percent 才自更新）。
 * 每次修改写一条 settings:rollout 审计。
 */
import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { getRollout, setRollout, validateRollout, ROLLOUT_CHANNELS } from '@/lib/rollout';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ rollout: getRollout(), channels: ROLLOUT_CHANNELS }, { headers: NO_STORE });
}

export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const { ok, problems, value } = validateRollout(body);
  if (!ok) return NextResponse.json({ error: 'validation_failed', details: problems }, { status: 400, headers: NO_STORE });

  await ensureBaselinesLoaded().catch(() => {});
  const saved = setRollout(value, session?.subject ?? 'console');
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'settings:rollout',
    resource_type: 'policy',
    detail: `自更新灰度设为 enabled=${saved.enabled} channel=${saved.channel} rollout_percent=${saved.rollout_percent}（下次发布策略生效）`,
  });
  return NextResponse.json({ rollout: saved }, { headers: NO_STORE });
}
