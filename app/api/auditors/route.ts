import { NextResponse } from 'next/server';
import { requireAdmin, requireAuditor } from '@/lib/auth';
import { getAuditorStore, addAuditor, removeAuditor, logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/auditors — list the auditor allowlist (admin + auditor read).
 * Auditors are read-only compliance reviewers: they can read the audit trail
 * and the admin/auditor rosters but cannot mutate anything.
 */
export async function GET(request: Request) {
  const denied = requireAuditor(request);
  if (denied) return denied;
  const envAuditors = (process.env.AEGIS_AUDITOR_USERS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const persisted = getAuditorStore();
  const combined = [...new Set([...envAuditors, ...persisted])];
  return NextResponse.json(
    { auditors: combined, persisted, env: envAuditors },
    { headers: NO_STORE },
  );
}

/** POST /api/auditors { employeeNo } — grant the auditor role (admin-only). */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE });
  }
  const employeeNo = String(body.employeeNo ?? '').trim();
  if (!/^[A-Za-z0-9]{3,32}$/.test(employeeNo)) {
    return NextResponse.json({ error: 'invalid_employee_no' }, { status: 400, headers: NO_STORE });
  }
  const added = addAuditor(employeeNo);
  logAudit({
    actor: 'console',
    action: 'auditor:add',
    resource_type: 'system',
    resource_id: employeeNo,
    detail: added ? 'added' : 'already_exists',
  });
  return NextResponse.json(
    { added, employeeNo },
    { status: added ? 201 : 200, headers: NO_STORE },
  );
}

/** DELETE /api/auditors?employeeNo=X — revoke the auditor role (admin-only). */
export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const employeeNo = (url.searchParams.get('employeeNo') ?? '').trim();
  if (!employeeNo) {
    return NextResponse.json({ error: 'missing_employee_no' }, { status: 400, headers: NO_STORE });
  }
  const removed = removeAuditor(employeeNo);
  logAudit({
    actor: 'console',
    action: 'auditor:remove',
    resource_type: 'system',
    resource_id: employeeNo,
    detail: removed ? 'removed' : 'not_found',
  });
  return NextResponse.json({ removed, employeeNo }, { headers: NO_STORE });
}
