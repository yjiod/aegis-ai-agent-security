import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Validates against AEGIS_CONSOLE_USER / AEGIS_CONSOLE_PASSWORD env vars.
 * On success sets an HMAC-signed session cookie (7 day expiry).
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const username = String(body.username ?? '').trim();
  const password = String(body.password ?? '');

  const expectedUser = process.env.AEGIS_CONSOLE_USER ?? 'admin';
  const expectedPass = process.env.AEGIS_CONSOLE_PASSWORD ?? '';

  if (!expectedPass) {
    return json({ error: 'auth_not_configured', hint: 'Set AEGIS_CONSOLE_PASSWORD on the server' }, 503);
  }

  // Constant-time comparison
  const userOk = username.length === expectedUser.length &&
    username.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedUser.charCodeAt(i)), 0) === 0;
  const passOk = password.length === expectedPass.length &&
    password.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedPass.charCodeAt(i)), 0) === 0;

  if (!userOk || !passOk) {
    return json({ error: 'invalid_credentials' }, 401);
  }

  // Create signed session token
  const secret = process.env.AEGIS_SESSION_SECRET ?? expectedPass;
  const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
  const payload = `${username}.${expiry}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
  const token = `${payload}.${sigHex}`;

  const response = json({ ok: true, username, expiry });
  response.cookies.set('aegis_session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60,
  });
  return response;
}

/** GET /api/auth/login — check current session */
export async function GET() {
  return json({ authenticated: false, hint: 'POST to login' }, 401);
}
