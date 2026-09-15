import { NextResponse } from 'next/server';
import { requireAdmin, requireAuditor, getSession, invalidateOperatorCache, operatorAllowlist } from '@/lib/auth';
import { pgGetOperators, pgSetOperators } from '@/lib/pg-store';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' } as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

const EMPLOYEE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * /api/operators — 运维工程师（operator）白名单管理（4A · capability RBAC 批2b）。
 * 持久化在 PG settings 表 allowlist:operators（JSON 数组），与 env AEGIS_OPERATOR_USERS
 * 取并集。GET 供 admin/auditor 查阅；POST/DELETE 仅 admin。写后 invalidate 缓存。
 * operator 档能力见 lib/auth.canWriteDevices（仅 device:write）。
 */
export async function GET(request: Request) {
  const denied = requireAuditor(request);
  if (denied) return denied;
  const persisted = (await pgGetOperators().catch(() => null)) ?? [];
  const env = [...operatorAllowlist()].filter((s) => !persisted.includes(s));
  return json({ operators: persisted, env_operators: env });
}

export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const employeeNo = String(body.employeeNo ?? '').trim();
  if (!EMPLOYEE_PATTERN.test(employeeNo)) return json({ error: 'invalid_employee_no' }, 400);

  const current = (await pgGetOperators().catch(() => null)) ?? [];
  if (current.includes(employeeNo)) return json({ error: 'already_operator' }, 409);
  const saved = await pgSetOperators([...current, employeeNo]);
  if (!saved) return json({ error: 'credential_store_unavailable', hint: 'PG 不可用，未持久化' }, 503);
  invalidateOperatorCache();
  logAudit({ actor: getSession(request)?.subject ?? 'admin', action: 'operator:add', resource_type: 'system', resource_id: employeeNo });
  return json({ ok: true, employeeNo }, 201);
}

export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const employeeNo = (url.searchParams.get('employeeNo') ?? '').trim();
  if (!employeeNo) return json({ error: 'missing_employee_no' }, 400);

  const current = (await pgGetOperators().catch(() => null)) ?? [];
  if (!current.includes(employeeNo)) return json({ error: 'not_found' }, 404);
  const saved = await pgSetOperators(current.filter((s) => s !== employeeNo));
  if (!saved) return json({ error: 'credential_store_unavailable' }, 503);
  invalidateOperatorCache();
  logAudit({ actor: getSession(request)?.subject ?? 'admin', action: 'operator:remove', resource_type: 'system', resource_id: employeeNo });
  return json({ ok: true, employeeNo });
}
