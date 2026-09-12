import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { getAdminStore, addAdmin, removeAdmin, logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

/** GET /api/admins — list persisted SSO admins (admin-only). */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const envAdmins = (process.env.AEGIS_ADMIN_USERS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const persisted = getAdminStore();
  const combined = [...new Set([...envAdmins, ...persisted])];
  return NextResponse.json(
    { admins: combined, persisted, env: envAdmins },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}

/** POST /api/admins { employeeNo } — add an SSO admin (admin-only). */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400 }); }
  const employeeNo = String(body.employeeNo ?? '').trim();
  if (!/^[A-Za-z0-9]{3,32}$/.test(employeeNo)) return NextResponse.json({ error: 'invalid_employee_no' }, { status: 400 });
  const added = addAdmin(employeeNo);
  logAudit({ actor: 'console', action: 'admin:add', resource_type: 'system', resource_id: employeeNo, detail: added ? 'added' : 'already_exists' });
  return NextResponse.json({ added, employeeNo }, { status: added ? 201 : 200 });
}

/** DELETE /api/admins?employeeNo=X — remove an SSO admin (admin-only). */
export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const employeeNo = (url.searchParams.get('employeeNo') ?? '').trim();
  if (!employeeNo) return NextResponse.json({ error: 'missing_employee_no' }, { status: 400 });
  if (employeeNo === 'admin') return NextResponse.json({ error: 'cannot_remove_local_admin' }, { status: 400 });
  const removed = removeAdmin(employeeNo);
  logAudit({ actor: 'console', action: 'admin:remove', resource_type: 'system', resource_id: employeeNo, detail: removed ? 'removed' : 'not_found' });
  return NextResponse.json({ removed, employeeNo });
}
