import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { probeIntegrations } from '@/lib/integrations';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/integrations — 集成控制面(admin): 各平台健康+能力+告警计数。
 * 配置来源 settings(integration.*) > env(AEGIS_INT_*)。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const integrations = await probeIntegrations();
  return NextResponse.json({ integrations }, { headers: NO_STORE });
}
