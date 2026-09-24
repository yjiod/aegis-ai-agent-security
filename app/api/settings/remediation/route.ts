import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { ensureBaselinesLoaded, setSetting } from '@/lib/baselines';
import { remediationConfig, type RemediationConfig } from '@/lib/auto-remediation';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET/PUT /api/settings/remediation — 自动纠偏配置（绝对要求 #3 的总开关）。
 * {enabled, auto_deny, notify}，默认全开；写操作留审计。
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  await ensureBaselinesLoaded().catch(() => {});
  return NextResponse.json({ config: remediationConfig() }, { headers: NO_STORE });
}

export async function PUT(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  let body: Record<string, unknown> = {};
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const clean: RemediationConfig = {
    enabled: typeof body.enabled === 'boolean' ? body.enabled : true,
    auto_deny: typeof body.auto_deny === 'boolean' ? body.auto_deny : true,
    notify: typeof body.notify === 'boolean' ? body.notify : true,
  };
  await ensureBaselinesLoaded().catch(() => {});
  setSetting('remediation_json', JSON.stringify(clean), session?.subject ?? 'console');
  logAudit({
    actor: session?.subject ?? 'console',
    action: 'settings:remediation',
    resource_type: 'system',
    detail: `自动纠偏配置: enabled=${clean.enabled} auto_deny=${clean.auto_deny} notify=${clean.notify}`,
  });
  return NextResponse.json({ config: clean }, { headers: NO_STORE });
}
