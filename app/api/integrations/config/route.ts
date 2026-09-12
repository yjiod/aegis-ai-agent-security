import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { getIntegrationsConfig, setIntegrationConfig } from '@/lib/integrations';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

const MASK = (v: string) => (v ? `${v.slice(0, 4)}…(${v.length})` : '');

/** GET /api/integrations/config — 读集成配置(token 打码)。 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const c = getIntegrationsConfig();
  return NextResponse.json(
    {
      fleet_url: c.fleet_url,
      fleet_token: MASK(c.fleet_token),
      wazuh_url: c.wazuh_url,
      wazuh_user: c.wazuh_user,
      wazuh_pass: MASK(c.wazuh_pass),
      pf_url: c.pf_url,
      pf_token: MASK(c.pf_token),
    },
    { headers: NO_STORE },
  );
}

/** PUT /api/integrations/config — 更新集成配置(admin); 空字符串=清除该键。 */
export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const allowed = ['fleet_url', 'fleet_token', 'wazuh_url', 'wazuh_user', 'wazuh_pass', 'pf_url', 'pf_token'];
  const patch: Record<string, string> = {};
  for (const k of allowed) {
    if (typeof body[k] === 'string') patch[k] = String(body[k]);
  }
  setIntegrationConfig(patch, session?.subject ?? 'console');
  return NextResponse.json({ updated: Object.keys(patch) }, { headers: NO_STORE });
}
