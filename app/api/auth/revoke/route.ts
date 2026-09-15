import { NextResponse } from 'next/server';
import { requireAdmin, getSession, revokeSessions } from '@/lib/auth';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' } as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/**
 * POST /api/auth/revoke — 管理员显式吊销某 subject 的全部会话（4A · 会话生命周期）。
 * Body: { subject }
 *
 * 写入 session_invalid_before:<subject> = now，凡签发早于该时间的会话即刻失效
 * （middleware 页面跳转 + 各路由 parseSession 401 双重强制）。用于离职/换岗/
 * 会话泄露等场景的跨设备强制下线。仅 admin 可调用；操作本身留审计。
 * PG 不可用时如实返回 503（不假装吊销成功）。
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const subject = String(body.subject ?? '').trim().slice(0, 128);
  if (!subject) return json({ error: 'invalid_subject' }, 400);

  const actor = getSession(request)?.subject ?? 'admin';
  const ok = await revokeSessions(subject);
  if (!ok) {
    logAudit({ actor, action: 'auth:session_revoke_failed', resource_type: 'system', detail: `subject=${subject} reason=store_unavailable` });
    return json({ error: 'credential_store_unavailable', hint: '凭据存储（PG）不可用，未吊销' }, 503);
  }
  logAudit({ actor, action: 'auth:session_revoke', resource_type: 'system', detail: `subject=${subject}` });
  return json({ ok: true, revoked: subject });
}
