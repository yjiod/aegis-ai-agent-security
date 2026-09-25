import { NextResponse } from 'next/server';
import { requireSession } from '@/lib/auth';
import { ensureLabelsLoaded, allowedAssetKeys, isFindingAllowed } from '@/lib/labels';

export const dynamic = 'force-dynamic';

/**
 * GET /api/devices/:id/findings?limit=N
 * Proxies the Collector /v1/findings for a device (latest report findings)
 * so the console can triage individual findings.
 *
 * 加白抑制：已处置为 allow 的同源资产发现从列表中剔除（与 /api/findings 一致），
 * 并回传 suppressed 计数，保证"已加白不再告警"在设备下钻视图同样成立。
 * 原始发现仍留存于 Collector（审计留痕不销毁）。
 */
export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
  // 会话验签闸（契约声明 /devices/{id}/findings = session）：middleware 不验签，
  // 伪造 Cookie 能过 middleware，此处必须真验签，否则可枚举任意设备的原始发现。
  const __denied = requireSession(request);
  if (__denied) return __denied;
  const { id } = await ctx.params;
  const url = new URL(request.url);
  const limit = Math.min(Number(url.searchParams.get('limit') ?? 200), 1000);

  const collector = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!collector || !token) return NextResponse.json({ error: 'collector_not_configured' }, { status: 503 });

  try {
    const res = await fetch(`${collector.replace(/\/$/, '')}/v1/findings?device_id=${encodeURIComponent(id)}&limit=${limit}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404) return NextResponse.json({ error: 'device_not_found' }, { status: 404 });
    if (!res.ok) return NextResponse.json({ error: 'collector_unavailable' }, { status: 503 });
    const data = (await res.json()) as Record<string, unknown> & { findings?: unknown };
    await ensureLabelsLoaded().catch(() => {});
    const allowed = allowedAssetKeys();
    if (Array.isArray(data.findings)) {
      let suppressed = 0;
      const kept = (data.findings as Array<Record<string, unknown>>).filter((f) => {
        if (isFindingAllowed(f, allowed)) { suppressed += 1; return false; }
        return true;
      });
      data.findings = kept;
      data.suppressed = suppressed;
    }
    return NextResponse.json(data, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return NextResponse.json({ error: 'collector_unavailable' }, { status: 503 });
  }
}
