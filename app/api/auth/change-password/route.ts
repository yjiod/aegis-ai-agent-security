import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/**
 * POST /api/auth/change-password
 * Body: { current_password, new_password }
 * Validates current password against AEGIS_CONSOLE_PASSWORD env var.
 * On success, the new password must be persisted server-side.
 *
 * NOTE: In the wrangler/VPS deployment, env vars are read-only at runtime.
 * Password changes are written to a server-side file (/etc/aegis/console-password)
 * that the systemd service / wrangler reads on restart. For the current
 * deployment, this endpoint validates and returns instructions; the actual
 * persistence requires a server-side write which is handled by the
 * deployment wrapper (see docs/DEPLOYMENT.md).
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const current = String(body.current_password ?? '');
  const next = String(body.new_password ?? '');

  const expectedPass = process.env.AEGIS_CONSOLE_PASSWORD ?? '';
  if (!expectedPass) return json({ error: 'auth_not_configured' }, 503);

  // Constant-time compare current password
  const ok = current.length === expectedPass.length &&
    current.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedPass.charCodeAt(i)), 0) === 0;
  if (!ok) return json({ error: 'invalid_current_password' }, 401);

  if (next.length < 8) return json({ error: 'password_too_short', hint: '至少 8 个字符' }, 400);

  // In a full deployment this would persist the new password.
  // For the current VPS + wrangler setup, we signal success and the
  // operator updates AEGIS_CONSOLE_PASSWORD then restarts aegis-console.
  return json({
    ok: true,
    message: '密码验证通过。生产环境请更新服务器 AEGIS_CONSOLE_PASSWORD 后重启 aegis-console 服务生效。',
  });
}
