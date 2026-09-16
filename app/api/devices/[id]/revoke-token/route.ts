import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: NO_STORE });
}

/**
 * POST /api/devices/:id/revoke-token — 吊销某终端的每设备上报令牌（批4，仅 admin）。
 * 调用 Collector DELETE /v1/device-tokens?device_id= 删除该设备全部每设备令牌；
 * 该终端下次上报将 401，Agent 0.33.1 的自愈逻辑会自动重新入网领取新令牌。
 * 用于终端失陷/离职/换机时的快速止损，不影响其他终端（每设备令牌相互独立）。
 */
export async function POST(request: Request, ctx: { params: Promise<{ id: string }> }) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const { id } = await ctx.params;
  const deviceId = (id ?? '').trim();
  if (!/^[0-9a-f]{12}$/.test(deviceId)) return json({ error: 'invalid_device_id' }, 400);

  const url = process.env.AEGIS_COLLECTOR_URL;
  const admin = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !admin) return json({ error: 'collector_not_configured' }, 503);

  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/device-tokens?device_id=${encodeURIComponent(deviceId)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin}` },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return json({ error: 'collector_revoke_failed', status: res.status }, 502);
    const body = (await res.json().catch(() => ({}))) as { revoked?: number };
    logAudit({
      actor: getSession(request)?.subject ?? 'admin',
      action: 'device:revoke_token',
      resource_type: 'device',
      resource_id: deviceId,
      detail: `吊销每设备上报令牌 revoked=${body.revoked ?? 0}（终端下次上报 401 后将自愈重入网）`,
    });
    return json({ ok: true, revoked: body.revoked ?? 0 });
  } catch {
    return json({ error: 'collector_unreachable' }, 502);
  }
}
