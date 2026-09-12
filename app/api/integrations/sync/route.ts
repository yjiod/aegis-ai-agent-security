import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { syncIntegrationAlerts } from '@/lib/integrations';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** POST /api/integrations/sync — 手动把各平台告警同步为去重工单(admin)。定时循环每10分钟自动跑。 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  const created = await syncIntegrationAlerts().catch(() => 0);
  logAudit({ actor: session?.subject ?? 'console', action: 'integrations:sync', resource_type: 'system', detail: `created=${created}` });
  return NextResponse.json({ created }, { headers: NO_STORE });
}
