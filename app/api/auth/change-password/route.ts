import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';
import { loadPasswordHash, verifyPassword, savePasswordHash } from '@/lib/credentials';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/**
 * POST /api/auth/change-password
 * Body: { current_password, new_password }
 *
 * 4A 凭据生命周期（真实持久化）：校验当前密码（优先持久化哈希、回落 env），
 * 随后把新密码以 PBKDF2-SHA256 哈希写入 PG settings 表并**同步确认**写入结果。
 * 写入成功才返回"已修改"；PG 未配置/不可达时如实返回 credential_store_unavailable
 * 且不改任何凭据——绝不假装成功（红线）。登录端 login 会优先校验该持久化哈希。
 */
export async function POST(request: Request) {
  const __denied = requireAdmin(request);
  if (__denied) return __denied;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const current = String(body.current_password ?? '');
  const next = String(body.new_password ?? '');
  const actor = getSession(request)?.subject ?? 'anonymous';
  const subject = process.env.AEGIS_CONSOLE_USER ?? 'admin';

  const expectedPass = process.env.AEGIS_CONSOLE_PASSWORD ?? '';
  const persistedHash = await loadPasswordHash(subject);
  if (!persistedHash && !expectedPass) return json({ error: 'auth_not_configured' }, 503);

  // 校验当前密码：优先持久化哈希，回落 env（与 login 同序）。
  const ok = persistedHash
    ? await verifyPassword(current, persistedHash)
    : current.length === expectedPass.length &&
      current.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedPass.charCodeAt(i)), 0) === 0;
  if (!ok) {
    logAudit({ actor, action: 'auth:password_change_failed', resource_type: 'system', detail: 'reason=invalid_current_password' });
    return json({ error: 'invalid_current_password' }, 401);
  }

  if (next.length < 8) return json({ error: 'password_too_short', hint: '至少 8 个字符' }, 400);

  // 真实持久化并确认；失败则如实报错、不改动凭据。
  const saved = await savePasswordHash(subject, next);
  if (!saved) {
    logAudit({ actor, action: 'auth:password_change_failed', resource_type: 'system', detail: 'reason=credential_store_unavailable' });
    return json({
      error: 'credential_store_unavailable',
      hint: '凭据存储（PG）不可用，未修改密码；请检查 AEGIS_PG_URL 后重试',
    }, 503);
  }

  logAudit({ actor, action: 'auth:password_change', resource_type: 'system', detail: 'persisted to credential store' });
  return json({ ok: true, message: '密码已修改并持久化，下次登录使用新密码。' });
}
