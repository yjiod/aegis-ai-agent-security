import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

export interface TrendBucket {
  t: number;
  reports: number;
  critical: number;
  high: number;
}
export interface TrendPayload {
  generated_at: number;
  hours: number;
  buckets: TrendBucket[];
}

function unavailable(error: string, status = 503): NextResponse {
  return NextResponse.json({ error, buckets: [] as TrendBucket[], connected: false }, { status, headers: NO_STORE });
}

/**
 * GET /api/trend?hours=N — 首页趋势图数据源（近 N 小时按小时分桶的上报/严重/高危数）。
 * 代理 Collector /v1/trend（走 received_at 索引区间扫 + 小时桶 GROUP BY，非全表）。
 * 未连接/配置无效时诚实返回 connected:false + 空桶，绝不伪造趋势。
 */
export async function GET(request: Request): Promise<NextResponse> {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });

  const url = new URL(request.url);
  const hoursRaw = Number(url.searchParams.get('hours') ?? 24);
  const hours = Number.isFinite(hoursRaw) ? Math.min(Math.max(Math.round(hoursRaw), 1), 168) : 24;

  const collectorUrl = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  const allowedHost = process.env.AEGIS_COLLECTOR_ALLOWED_HOST ?? '';
  if (!collectorUrl || !token) return unavailable('collector_not_configured');

  let target: URL;
  try {
    const base = new URL(collectorUrl);
    const isLocalhost = base.hostname === '127.0.0.1' || base.hostname === 'localhost' || base.hostname === '[::1]';
    if (
      (!isLocalhost && base.protocol !== 'https:') ||
      (allowedHost && base.hostname.toLowerCase() !== allowedHost.toLowerCase()) ||
      base.username ||
      base.password ||
      base.hash ||
      token.length < 32 ||
      token.length > 4096
    )
      return unavailable('collector_configuration_invalid');
    target = new URL(`/v1/trend?hours=${hours}`, base.origin);
  } catch {
    return unavailable('collector_configuration_invalid');
  }

  try {
    const response = await fetch(target, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });
    if (!response.ok) return unavailable('collector_unreachable', response.status === 404 ? 404 : 503);
    const data = (await response.json()) as TrendPayload;
    if (!Array.isArray(data.buckets)) return unavailable('collector_bad_payload');
    return NextResponse.json({ ...data, connected: true }, { headers: NO_STORE });
  } catch {
    return unavailable('collector_unreachable');
  }
}
