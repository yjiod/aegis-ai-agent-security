import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

export interface CollectorConfigValue {
  value: number;
  override: boolean;
  min: number;
  max: number;
}
export interface CollectorConfig {
  generated_at: number;
  config: Record<string, CollectorConfigValue>;
}

function collectorBase(): { url: string; token: string } | null {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/$/, ''), token };
}

/**
 * GET/PUT /api/settings/retention — 控制台「全局配置」中数据保留期 / 审计保留 / 审计封顶
 * 的真实读写通道：代理 Collector /v1/config（运行时配置覆盖，优先于 collector env）。
 * GET 任意已认证身份可读；PUT 仅 admin。Collector 不可达时如实 502/503，不伪造配置。
 */
export async function GET(request: Request): Promise<NextResponse> {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  const base = collectorBase();
  if (!base) return NextResponse.json({ error: 'collector_not_configured' }, { status: 503, headers: NO_STORE });
  try {
    const res = await fetch(`${base.url}/v1/config`, {
      headers: { Authorization: `Bearer ${base.token}`, Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return NextResponse.json({ error: 'collector_unreachable', status: res.status }, { status: 502, headers: NO_STORE });
    const data = (await res.json()) as CollectorConfig;
    return NextResponse.json(data, { headers: NO_STORE });
  } catch {
    return NextResponse.json({ error: 'collector_unreachable' }, { status: 502, headers: NO_STORE });
  }
}

export async function PUT(request: Request): Promise<NextResponse> {
  const denied = requireAdmin(request);
  if (denied) return denied;
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const allowed = ['retention_days', 'audit_retention_days', 'audit_max_events'];
  const payload: Record<string, number> = {};
  for (const key of allowed) {
    if (body[key] === undefined) continue;
    const n = Number(body[key]);
    if (!Number.isInteger(n)) return NextResponse.json({ error: 'invalid_value', details: [key] }, { status: 400, headers: NO_STORE });
    payload[key] = n;
  }
  if (Object.keys(payload).length === 0) {
    return NextResponse.json({ error: 'invalid_body', details: ['expect one of ' + allowed.join('/')] }, { status: 400, headers: NO_STORE });
  }
  const base = collectorBase();
  if (!base) return NextResponse.json({ error: 'collector_not_configured' }, { status: 503, headers: NO_STORE });
  try {
    const res = await fetch(`${base.url}/v1/config`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${base.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      return NextResponse.json({ error: (data.error as string) ?? 'collector_rejected', details: data.details }, { status: res.status, headers: NO_STORE });
    }
    return NextResponse.json(data, { headers: NO_STORE });
  } catch {
    return NextResponse.json({ error: 'collector_unreachable' }, { status: 502, headers: NO_STORE });
  }
}
