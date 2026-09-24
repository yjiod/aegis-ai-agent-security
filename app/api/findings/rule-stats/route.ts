import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

export interface RuleStat {
  rule_id: string;
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}
export interface RuleStatsPayload {
  generated_at: number;
  complete: boolean;
  processed: number;
  last_report_id: number;
  rule_stats: RuleStat[];
}

function unavailable(error: string, status = 503): NextResponse {
  return NextResponse.json(
    { error, connected: false, complete: false, rule_stats: [] as RuleStat[] },
    { status, headers: NO_STORE },
  );
}

/**
 * GET /api/findings/rule-stats — fleet 级 per-rule 检测计数（技战法活跃态势的权威数据源）。
 * 代理 Collector /v1/findings/rule-stats（服务端增量聚合，水位线推进，非客户端样本推断）。
 * 未连接 / 旧 Collector 无该端点(404) 时诚实返回 connected:false，控制台回落样本口径并如实标注。
 */
export async function GET(request: Request): Promise<NextResponse> {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });

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
    target = new URL('/v1/findings/rule-stats', base.origin);
  } catch {
    return unavailable('collector_configuration_invalid');
  }

  try {
    const response = await fetch(target, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });
    if (response.status === 404) return unavailable('collector_endpoint_missing', 404);
    if (!response.ok) return unavailable('collector_unreachable', 503);
    const data = (await response.json()) as RuleStatsPayload;
    if (!Array.isArray(data.rule_stats)) return unavailable('collector_bad_payload');
    return NextResponse.json({ ...data, connected: true }, { headers: NO_STORE });
  } catch {
    return unavailable('collector_unreachable');
  }
}
