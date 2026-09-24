import { NextResponse } from 'next/server';
import { logAudit } from '@/lib/store';
import { pgGetMfa } from '@/lib/pg-store';
import { issueMfaToken } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/**
 * GET /api/auth/oidc/callback?code=...&state=...
 * Exchanges the OIDC authorization code for tokens, extracts the subject,
 * and issues the Aegis session cookie. Works with any standard OIDC IdP
 * (Authelia / Keycloak / Casdoor / Authing / Azure AD / custom 4A OIDC).
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const err = url.searchParams.get('error');
  if (err) return NextResponse.redirect(new URL(`/login?error=${encodeURIComponent(err)}`, url.origin));
  if (!code) return NextResponse.redirect(new URL('/login?error=missing_code', url.origin));

  const issuer = process.env.AEGIS_OIDC_ISSUER ?? '';
  const clientId = process.env.AEGIS_OIDC_CLIENT_ID ?? '';
  const clientSecret = process.env.AEGIS_OIDC_CLIENT_SECRET ?? '';
  const sessionSecret = process.env.AEGIS_SESSION_SECRET ?? '';
  if (!issuer || !clientId) return NextResponse.redirect(new URL('/login?error=oidc_not_configured', url.origin));

  const redirectUri = `${url.origin}/api/auth/oidc/callback`;

  let tokens: { id_token?: string } = {};
  try {
    const tokenRes = await fetch(`${issuer.replace(/\/$/, '')}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (!tokenRes.ok) return NextResponse.redirect(new URL('/login?error=token_exchange_failed', url.origin));
    tokens = (await tokenRes.json()) as { id_token?: string };
  } catch {
    return NextResponse.redirect(new URL('/login?error=token_exchange_failed', url.origin));
  }

  let subject = 'oidc-user';
  let email = '';
  if (tokens.id_token) {
    try {
      const part = tokens.id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(atob(part));
      subject = String(payload.sub ?? payload.preferred_username ?? 'oidc-user');
      email = String(payload.email ?? '');
    } catch { /* default subject */ }
  }

  const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payloadStr = `${subject}.${expiry}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(sessionSecret || clientSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadStr));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');

  // 4A · Accounting：SSO 登录成功留审计（actor=IdP subject）。
  logAudit({ actor: subject, action: 'auth:sso_login', resource_type: 'system', detail: 'method=oidc' });

  // 4A · MFA 步进：IdP 通过后若该 subject 已启用 TOTP，**不直接签发会话**；改发短期 mfa
  // 挑战并经 URL fragment 回 /login 完成第二步（fragment 不进服务端日志与浏览历史）。
  // 真机反馈：启用 MFA 后走 SSO 未弹第二步 → 会话被直接签发，MFA 形同虚设。
  const mfa = await pgGetMfa(subject).catch(() => null);
  if (mfa?.enabled) {
    logAudit({ actor: subject, action: 'auth:mfa_challenge', resource_type: 'system', detail: 'method=oidc' });
    const mfaToken = issueMfaToken(subject);
    return NextResponse.redirect(new URL(`/login#mfa=${encodeURIComponent(mfaToken)}`, url.origin));
  }

  const response = NextResponse.redirect(new URL('/', url.origin));
  response.cookies.set('aegis_session', `${payloadStr}.${sigHex}`, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 7 * 24 * 60 * 60,
  });
  response.cookies.set('aegis_user', encodeURIComponent(email || subject), { path: '/', maxAge: 7 * 24 * 60 * 60 });
  return response;
}
