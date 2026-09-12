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

  // OIDC
  const issuer = process.env.AEGIS_OIDC_ISSUER ?? '';
  const clientId = process.env.AEGIS_OIDC_CLIENT_ID ?? '';
  const oidcEnabled = provider === 'oidc' && Boolean(issuer) && Boolean(clientId);
  let authorizeUrl = '';
  if (oidcEnabled) {
    const redirectUri = `${url.origin}/api/auth/oidc/callback`;
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
    const redirectUri = `${url.origin}/api/auth/uac/callback`;
    // UAC portal: https://pfuac.transsion.com/#/c-login?appId&redirect
    const portal = process.env.AEGIS_UAC_PORTAL ?? 'https://pfuac.transsion.com/#/c-login';
    uacUrl = `${portal}?appId=${encodeURIComponent(uacAppId)}&redirect=${encodeURIComponent(redirectUri)}`;
  }

  const ssoEnabled = oidcEnabled || uacEnabled;
  return NextResponse.json(
    {
      provider,
      oidc_enabled: oidcEnabled,
      uac_enabled: uacEnabled,
      authorize_url: oidcEnabled ? authorizeUrl : uacEnabled ? uacUrl : '',
      idp_label: process.env.AEGIS_OIDC_LABEL ?? (uacEnabled ? '传音统一身份登录' : '统一身份登录'),
      sso_enabled: ssoEnabled,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
