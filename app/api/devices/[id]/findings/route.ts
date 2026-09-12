import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * GET /api/devices/:id/findings?limit=N
 * Proxies the Collector /v1/findings for a device (latest report findings)
 * so the console can triage individual findings.
 */
export async function GET(request: Request, ctx: { params: Promise<{ id: string }> }) {
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
    const data = await res.json();
    return NextResponse.json(data, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return NextResponse.json({ error: 'collector_unavailable' }, { status: 503 });
  }
}
