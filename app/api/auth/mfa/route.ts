import { NextResponse } from 'next/server';
import { getSession, verifyMfaToken, signSessionToken, attachSessionCookie } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { pgGetMfa, pgSetMfa } from '@/lib/pg-store';
import { generateTotpSecret, verifyTotp, otpauthUri } from '@/lib/totp';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' } as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/**
 * /api/auth/mfa — TOTP 两步验证生命周期（4A · Authentication）。
 *
 * GET  { }                        -> 当前会话 subject 的 MFA 状态 {enabled}
 * POST { action:'enroll' }        -> 生成待确认密钥，返回 base32 secret + otpauth:// URI
 * POST { action:'confirm', code } -> 校验一个有效码后启用（防绑错设备）
 * POST { action:'verify', mfa_token, code } -> 登录第二步：校验挑战+TOTP 后签发会话
 * POST { action:'disable', code } -> 校验码后停用（恢复单因素）
 *
 * 仅 enroll/confirm/disable 需要已登录会话（操作自身账号）；verify 属登录流程、
 * 凭短期 mfa_token（绑定 subject、5 分钟有效）而非会话。所有动作留审计。
 * PG 不可用时如实报错（不假装启用/验证成功）。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return json({ error: 'unauthenticated' }, 401);
  const mfa = await pgGetMfa(session.subject).catch(() => null);
  return json({ enabled: Boolean(mfa?.enabled) });
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const action = String(body.action ?? '');
  const code = String(body.code ?? '').trim();

  // ── verify：登录第二步（无会话，凭 mfa_token）──
  if (action === 'verify') {
    const subject = verifyMfaToken(String(body.mfa_token ?? ''));
    if (!subject) return json({ error: 'invalid_mfa_token' }, 401);
    const mfa = await pgGetMfa(subject).catch(() => null);
    if (!mfa?.enabled) return json({ error: 'mfa_not_enrolled' }, 400);
    const ok = await verifyTotp(mfa.secret, code);
    if (!ok) {
      logAudit({ actor: subject, action: 'auth:mfa_failed', resource_type: 'system', detail: 'reason=invalid_code' });
      return json({ error: 'invalid_mfa_code' }, 401);
    }
    const token = await signSessionToken(subject);
    const response = json({ ok: true, username: subject });
    attachSessionCookie(response, token);
    logAudit({ actor: subject, action: 'auth:login', resource_type: 'system', detail: 'method=second_factor' });
    return response;
  }

  // ── 其余动作需已登录会话（仅操作自身 subject，不能代他人绑定设备）──
  const session = getSession(request);
  if (!session) return json({ error: 'unauthenticated' }, 401);
  const subject = session.subject;

  if (action === 'enroll') {
    const secret = generateTotpSecret();
    const saved = await pgSetMfa(subject, { secret, enabled: false });
    if (!saved) return json({ error: 'credential_store_unavailable', hint: 'PG 不可用，未生成 MFA 密钥' }, 503);
    logAudit({ actor: subject, action: 'auth:mfa_enroll_started', resource_type: 'system' });
    return json({ secret, otpauth_uri: otpauthUri(secret, subject) });
  }

  if (action === 'confirm') {
    const mfa = await pgGetMfa(subject).catch(() => null);
    if (!mfa) return json({ error: 'mfa_not_enrolled', hint: '请先 enroll 获取密钥' }, 400);
    const ok = await verifyTotp(mfa.secret, code);
    if (!ok) {
      logAudit({ actor: subject, action: 'auth:mfa_confirm_failed', resource_type: 'system', detail: 'reason=invalid_code' });
      return json({ error: 'invalid_mfa_code' }, 400);
    }
    const saved = await pgSetMfa(subject, { secret: mfa.secret, enabled: true });
    if (!saved) return json({ error: 'credential_store_unavailable' }, 503);
    logAudit({ actor: subject, action: 'auth:mfa_enabled', resource_type: 'system' });
    return json({ ok: true, enabled: true });
  }

  if (action === 'disable') {
    const mfa = await pgGetMfa(subject).catch(() => null);
    if (!mfa?.enabled) return json({ error: 'mfa_not_enabled' }, 400);
    const ok = await verifyTotp(mfa.secret, code);
    if (!ok) {
      logAudit({ actor: subject, action: 'auth:mfa_disable_failed', resource_type: 'system', detail: 'reason=invalid_code' });
      return json({ error: 'invalid_mfa_code' }, 400);
    }
    const saved = await pgSetMfa(subject, { secret: '', enabled: false });
    if (!saved) return json({ error: 'credential_store_unavailable' }, 503);
    logAudit({ actor: subject, action: 'auth:mfa_disabled', resource_type: 'system' });
    return json({ ok: true, enabled: false });
  }

  return json({ error: 'unknown_action' }, 400);
}
