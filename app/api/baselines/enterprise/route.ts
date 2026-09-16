import { NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { requireAdmin, requireAuditor, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { pgGetSettings, pgSetSetting } from '@/lib/pg-store';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;
function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: NO_STORE });
}

const K_CONTENT = 'enterprise_md_content';
const K_VERSION = 'enterprise_md_version';
const K_ROLLOUT = 'enterprise_md_rollout';

// 写穿透缓存：pgSetSetting 为异步调度写，GET 紧随其后可能读不到 → 用模块缓存保证立即可见。
let cache: { content: string; version: number; rollout: ReturnType<typeof safeRollout> } | null = null;

/**
 * 企业级 MD（用户自有基线）上传/查看 + 灰度推送。
 *
 * - POST（仅 admin）：{ content, rollout:{mode:'all'|'percent'|'department', percent?, departments?[]} }
 *   → 版本自增存 PG settings，并推送到 Collector（POST /v1/enterprise-baseline，管理令牌），
 *     终端经 Collector 按灰度范围拉取（每设备令牌鉴权）。
 * - GET（admin/auditor）：返回当前版本/灰度配置/sha256/内容。
 *
 * 与上游同步基线完全分离：企业 MD 存独立键/独立表/终端独立文件
 * （enterprise-baseline.md），扫描时作为**附加**基线合并，不覆盖/不影响上游基线。
 */
export async function GET(request: Request) {
  const denied = requireAuditor(request);
  if (denied) return denied;
  if (!cache) {
    const settings = (await pgGetSettings().catch(() => null)) ?? {};
    const c = settings[K_CONTENT] ?? '';
    if (c) cache = { content: c, version: Number(settings[K_VERSION] ?? 0), rollout: safeRollout(settings[K_ROLLOUT]) };
  }
  if (!cache) return json({ published: false }, 404);
  return json({
    published: true,
    version: cache.version,
    rollout: cache.rollout,
    sha256: createHash('sha256').update(cache.content).digest('hex'),
    content: cache.content,
  });
}

export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const content = typeof body.content === 'string' ? body.content : '';
  if (content.length < 1 || content.length > 2_000_000) return json({ error: 'invalid_content' }, 400);
  const rollout = safeRollout(typeof body.rollout === 'object' && body.rollout ? JSON.stringify(body.rollout) : undefined);

  const settings = (await pgGetSettings().catch(() => null)) ?? {};
  const version = Number(settings[K_VERSION] ?? 0) + 1;
  pgSetSetting(K_CONTENT, content);
  pgSetSetting(K_VERSION, String(version));
  pgSetSetting(K_ROLLOUT, JSON.stringify(rollout));
  cache = { content, version, rollout };

  // 推送到 Collector（终端经其按灰度拉取）。Collector 不可达则返回 502（不假装已推送）。
  const collectorUrl = process.env.AEGIS_COLLECTOR_URL;
  const collectorToken = process.env.AEGIS_COLLECTOR_TOKEN;
  if (!collectorUrl || !collectorToken) return json({ error: 'collector_not_configured' }, 502);
  try {
    const r = await fetch(`${collectorUrl.replace(/\/$/, '')}/v1/enterprise-baseline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${collectorToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, version, rollout }),
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return json({ error: 'collector_push_failed', status: r.status }, 502);
  } catch {
    return json({ error: 'collector_unreachable' }, 502);
  }

  logAudit({
    actor: getSession(request)?.subject ?? 'admin',
    action: 'enterprise_md:publish',
    resource_type: 'policy',
    detail: `发布企业级 MD v${version} 灰度=${rollout.mode}${rollout.mode === 'percent' ? `:${rollout.percent}%` : ''}${rollout.mode === 'department' ? `:${(rollout.departments ?? []).join(',')}` : ''}`,
  });
  return json({ ok: true, version, rollout });
}

function safeRollout(raw?: string): { mode: 'all' | 'percent' | 'department'; percent?: number; departments?: string[] } {
  try {
    const r = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
    const mode = r.mode === 'percent' || r.mode === 'department' ? r.mode : 'all';
    const percent = mode === 'percent' ? Math.max(0, Math.min(100, Number(r.percent) || 0)) : undefined;
    const departments = mode === 'department' && Array.isArray(r.departments) ? (r.departments as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 200) : undefined;
    return { mode, ...(percent !== undefined ? { percent } : {}), ...(departments !== undefined ? { departments } : {}) };
  } catch {
    return { mode: 'all' };
  }
}
