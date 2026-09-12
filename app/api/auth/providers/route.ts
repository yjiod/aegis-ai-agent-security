import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * GET /api/auth/providers
 * Tells the login page which auth providers are available.
 *
 * - local: username/password against AEGIS_CONSOLE_PASSWORD (default)
 * - oidc:  standard OIDC IdP (Authelia/Keycloak/Casdoor/Authing/AzureAD/4A).
 *          Enabled when AEGIS_AUTH_PROVIDER=oidc + issuer + client_id.
 * - uac:   传音用户中心 (Transsion UAC) SSO. Enabled when
 *          AEGIS_AUTH_PROVIDER=uac + AEGIS_UAC_GATEWAY + AEGIS_UAC_APP_ID.
 *          Redirects to UAC portal; callback validates token + fetches user.
 */
export async function GET(request: Request) {
  const provider = process.env.AEGIS_AUTH_PROVIDER ?? 'local';
  const url = new URL(request.url);
  // Behind a TLS-terminating proxy (Caddy) url.origin is http; use forwarded proto.
  const proto = request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '');
  const publicOrigin = `${proto}://${url.host}`;

  // OIDC
  const issuer = process.env.AEGIS_OIDC_ISSUER ?? '';
  const clientId = process.env.AEGIS_OIDC_CLIENT_ID ?? '';
  const oidcEnabled = provider === 'oidc' && Boolean(issuer) && Boolean(clientId);
  let authorizeUrl = '';
  if (oidcEnabled) {
    const redirectUri = `${publicOrigin}/api/auth/oidc/callback`;
    const authorize = new URL(`${issuer.replace(/\/$/, '')}/authorize`);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', redirectUri);
    authorize.searchParams.set('scope', 'openid profile email');
    authorize.searchParams.set('state', crypto.randomUUID());
    authorizeUrl = authorize.toString();
  }

  // UAC (传音用户中心)
  const uacGateway = (process.env.AEGIS_UAC_GATEWAY ?? '').replace(/\/$/, '');
  const uacAppId = process.env.AEGIS_UAC_APP_ID ?? '';
  const uacEnabled = provider === 'uac' && Boolean(uacGateway) && Boolean(uacAppId);
  let uacUrl = '';
  if (uacEnabled) {
    // Redirect base: override (e.g. http://<IP> for UAT trust testing) or public origin
    const redirectBase = process.env.AEGIS_UAC_REDIRECT_BASE || publicOrigin;
    const redirectUri = `${redirectBase.replace(/\/$/, '')}/api/auth/uac/callback`;
    // UAC portal (new guide): {portal}?appId&lang&companyId&account&type&redirect
    // UAT portal carries a port, e.g. https://pfuacuat.transsion.com:10201/#/c-login
    const portal = process.env.AEGIS_UAC_PORTAL || 'https://pfuac.transsion.com/#/c-login';
    const lang = process.env.AEGIS_UAC_LANG || 'zh';
    const companyId = process.env.AEGIS_UAC_COMPANY_ID || '';
    const type = process.env.AEGIS_UAC_TYPE || 'simple';
    uacUrl =
      `${portal}?appId=${encodeURIComponent(uacAppId)}` +
      `&lang=${encodeURIComponent(lang)}` +
      `&companyId=${encodeURIComponent(companyId)}` +
      `&account=` +
      `&type=${encodeURIComponent(type)}` +
      `&redirect=${encodeURIComponent(redirectUri)}`;
  }

  const ssoEnabled = oidcEnabled || uacEnabled;
  const defaultLabel = uacEnabled ? '传音统一身份登录' : '统一身份登录';
  return NextResponse.json(
    {
      provider,
      oidc_enabled: oidcEnabled,
      uac_enabled: uacEnabled,
      authorize_url: oidcEnabled ? authorizeUrl : uacEnabled ? uacUrl : '',
      idp_label: process.env.AEGIS_OIDC_LABEL || defaultLabel,
      sso_enabled: ssoEnabled,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
