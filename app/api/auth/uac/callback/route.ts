import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * GET /api/auth/uac/callback?token=...&rtoken=...&employeeNo=...
 *
 * 传音用户中心 (UAC) SSO 回调。流程（对接指南 §二.1 登录门户）:
 *   1. 登录页重定向到 UAC 门户 (pfuac.transsion.com/#/c-login?appId&redirect)
 *   2. 用户在 UAC 完成登录
 *   3. UAC 回跳 redirect 地址并追加 token / rtoken / employeeNo
 *   4. 本回调校验 token (rtoken/check) → 获取用户信息 (utoken/getUserInfo)
 *   5. 签发 Aegis 会话 cookie
 *
 * 受限接口需 Header: P-Auth / P-Rtoken / P-AppId。
 * 网关: AEGIS_UAC_GATEWAY (如 https://sz-intra-paas.transsion.com)。
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const token =
    url.searchParams.get('token') ??
    url.searchParams.get('utoken') ??
    url.searchParams.get('accessToken') ??
    url.searchParams.get('access_token') ??
    '';
  const rtoken =
    url.searchParams.get('rtoken') ??
    url.searchParams.get('urtoken') ??
    url.searchParams.get('refreshToken') ??
    '';
  const employeeNo = url.searchParams.get('employeeNo') ?? url.searchParams.get('jobNumber') ?? '';
  const err = url.searchParams.get('error');

  if (err) return NextResponse.redirect(new URL(`/login?error=${encodeURIComponent(err)}`, url.origin));
  if (!token && !rtoken) {
    // Diagnose: report which query params the UAC portal actually appended.
    const got = [...url.searchParams.keys()].join(',') || '(none)';
    return NextResponse.redirect(new URL(`/login?error=missing_uac_token&got=${encodeURIComponent(got)}`, url.origin));
  }

  const gateway = (process.env.AEGIS_UAC_GATEWAY ?? '').replace(/\/$/, '');
  const appId = process.env.AEGIS_UAC_APP_ID ?? '';
  const sessionSecret = process.env.AEGIS_SESSION_SECRET ?? '';
  if (!gateway || !appId) return NextResponse.redirect(new URL('/login?error=uac_not_configured', url.origin));

  const uacHeaders = {
    'Content-Type': 'application/json',
    'P-Auth': token,
    'P-Rtoken': rtoken || token,
    'P-AppId': appId,
  };

  // 1) 校验 token 有效性: POST /uac-auth-service/v2/api/uac-auth/rtoken/check
  let subject = employeeNo || 'uac-user';
  let email = '';
  let department = '';
  try {
    const checkRes = await fetch(`${gateway}/uac-auth-service/v2/api/uac-auth/rtoken/check`, {
      method: 'POST', headers: uacHeaders, body: JSON.stringify({}),
    });
    if (!checkRes.ok) return NextResponse.redirect(new URL('/login?error=uac_token_invalid', url.origin));

    // 2) 获取用户信息: getUserInfo (doc: POST in SSO flow, GET in login-interface flow; try both)
    let infoRes = await fetch(`${gateway}/uac-auth-service/v2/api/uac-auth/utoken/getUserInfo`, {
      method: 'POST', headers: uacHeaders, body: JSON.stringify({}),
    });
    if (!infoRes.ok) {
      infoRes = await fetch(`${gateway}/uac-auth-service/v2/api/uac-auth/utoken/getUserInfo`, {
        method: 'GET', headers: uacHeaders,
      });
    }
    if (infoRes.ok) {
      const info = (await infoRes.json()) as Record<string, unknown>;
      const data = (info.data ?? info) as Record<string, unknown>;
      subject = String((data.employeeNo ?? data.jobNumber ?? employeeNo) || subject);
      email = String(data.email ?? data.mail ?? '');
      department = String(data.department ?? data.deptName ?? '');
    }
  } catch {
    return NextResponse.redirect(new URL('/login?error=uac_unreachable', url.origin));
  }

  // 3) 签发 Aegis 会话 cookie (HMAC, 与 local/oidc 同机制)
  const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payloadStr = `${subject}.${expiry}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(sessionSecret || appId), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadStr));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');

  const response = NextResponse.redirect(new URL('/', url.origin));
  // secure cookie only over https; http (IP-based UAT redirect) needs non-secure to persist
  const proto = request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '');
  const isHttps = proto === 'https';
  response.cookies.set('aegis_session', `${payloadStr}.${sigHex}`, {
    httpOnly: true, secure: isHttps, sameSite: 'lax', path: '/', maxAge: 7 * 24 * 60 * 60,
  });
  response.cookies.set('aegis_user', encodeURIComponent(email || subject), { path: '/', maxAge: 7 * 24 * 60 * 60 });
  if (department) response.cookies.set('aegis_dept', encodeURIComponent(department), { path: '/', maxAge: 7 * 24 * 60 * 60 });
  return response;
}
