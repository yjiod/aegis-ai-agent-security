/**
 * app/api/settings/alerting/route.ts — 舰队告警推送配置（admin 可写；Collector bearer 只读）。
 *
 * GET  : admin 会话 或 Authorization: Bearer <AEGIS_COLLECTOR_TOKEN>（服务器侧
 *        aegis_alert_check.py 用 Collector 令牌只读拉取，免 SSH 改 collector.env）。
 * PUT  : admin 设置 {enabled, webhook, format, offline_hours, min_interval_hours}。
 * POST : admin {test:true} → 向当前 webhook 发一条测试告警，返回发送结果。
 * 所有写操作留审计（settings:alerting / alerting:test）。
 */
import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded } from '@/lib/baselines';
import { logAudit } from '@/lib/store';
import { getAlertConfig, setAlertConfig, validateAlertConfig } from '@/lib/alerting';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

function collectorBearerOk(request: Request): boolean {
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!token) return false;
  const auth = request.headers.get('authorization') ?? '';
  return auth === `Bearer ${token}`;
}

export async function GET(request: Request) {
  const session = getSession(request);
  if (!session && !collectorBearerOk(request))
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ config: getAlertConfig() }, { headers: NO_STORE });
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
  await ensureBaselinesLoaded().catch(() => {});
  const { ok, problems, value } = validateAlertConfig(body);
  if (!ok) return NextResponse.json({ error: 'validation_failed', details: problems }, { status: 400, headers: NO_STORE });
  const saved = setAlertConfig(value, session?.subject ?? 'console');
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'settings:alerting',
    resource_type: 'system',
    detail: `告警推送配置更新: enabled=${saved.enabled} format=${saved.format} webhook=${saved.webhook ? 'set' : 'empty'} offline=${saved.offline_hours}h min_interval=${saved.min_interval_hours}h`,
  });
  return NextResponse.json({ config: saved }, { headers: NO_STORE });
}

export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  if (body.test !== true) return NextResponse.json({ error: 'invalid_body', details: ['expect {"test": true}'] }, { status: 400, headers: NO_STORE });
  await ensureBaselinesLoaded().catch(() => {});
  const cfg = getAlertConfig();
  if (!cfg.webhook) return NextResponse.json({ error: 'no_webhook', details: ['先配置 webhook 再测试'] }, { status: 400, headers: NO_STORE });
  const now = Date.now();
  const payload =
    cfg.format === 'dingtalk'
      ? { msgtype: 'text', text: { content: `Aegis 测试告警 ${new Date(now).toISOString()}（控制台手动测试）` } }
      : { schema: 'aegis.alert/v1', at: now, alerts: [{ type: 'test', device_id: 'console', hostname: 'console', severity: 'info', detail: 'console manual test' }] };
  try {
    const r = await fetch(cfg.webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000),
    });
    logAudit({ actor: session?.subject ?? 'console', action: 'alerting:test', resource_type: 'system', detail: `测试告警发送 status=${r.status}` });
    return NextResponse.json({ sent: true, status: r.status }, { headers: NO_STORE });
  } catch (e) {
    logAudit({ actor: session?.subject ?? 'console', action: 'alerting:test', resource_type: 'system', detail: `测试告警发送失败: ${e instanceof Error ? e.message : String(e)}` });
    return NextResponse.json({ sent: false, error: e instanceof Error ? e.message : String(e) }, { status: 502, headers: NO_STORE });
  }
}
