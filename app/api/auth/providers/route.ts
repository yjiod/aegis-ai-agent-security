import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * GET /api/auth/providers
 * Tells the login page which auth providers are available.
 * - local: username/password against AEGIS_CONSOLE_PASSWORD (default)
 * - oidc:  redirect to a standard OIDC IdP (any vendor: Authelia/Keycloak/
 *          Casdoor/Authing/AzureAD/custom 4A). Enabled when AEGIS_AUTH_PROVIDER=oidc
 *          and issuer+client_id are set.
 */
export async function GET(request: Request) {
  const provider = process.env.AEGIS_AUTH_PROVIDER ?? 'local';
  const issuer = process.env.AEGIS_OIDC_ISSUER ?? '';
  const clientId = process.env.AEGIS_OIDC_CLIENT_ID ?? '';
  const oidcEnabled = provider === 'oidc' && Boolean(issuer) && Boolean(clientId);

  let authorizeUrl = '';
  if (oidcEnabled) {
    const url = new URL(request.url);
    const redirectUri = `${url.origin}/api/auth/oidc/callback`;
    const authorize = new URL(`${issuer.replace(/\/$/, '')}/authorize`);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('client_id', clientId);
    authorize.searchParams.set('redirect_uri', redirectUri);
    authorize.searchParams.set('scope', 'openid profile email');
    authorize.searchParams.set('state', crypto.randomUUID());
    authorizeUrl = authorize.toString();
  }

  return NextResponse.json(
    {
      provider,
      oidc_enabled: oidcEnabled,
      authorize_url: authorizeUrl,
      idp_label: process.env.AEGIS_OIDC_LABEL ?? '统一身份登录',
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
