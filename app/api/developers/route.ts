import { NextResponse } from 'next/server';
import { requireAdmin, requireAuditor, getSession, invalidateDeveloperCache, developerAllowlist } from '@/lib/auth';
import { pgGetDevelopers, pgSetDevelopers } from '@/lib/pg-store';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' } as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

const EMPLOYEE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * /api/developers — 开发者（developer）白名单管理（4A · capability RBAC 持久化）。
 * 持久化在 PG settings 表 allowlist:developers（JSON 数组），与 env AEGIS_DEVELOPER_USERS
 * 取并集。GET 供 admin/auditor 查阅；POST/DELETE 仅 admin。写后 invalidate 缓存。
 * developer 档能力：仅可读"本人"设备（/api/devices 按 owner/os_user==subject 过滤），无写权限。
 */
export async function GET(request: Request) {
  const denied = requireAuditor(request);
  if (denied) return denied;
  const persisted = (await pgGetDevelopers().catch(() => null)) ?? [];
  const env = [...developerAllowlist()].filter((s) => !persisted.includes(s));
  return json({ developers: persisted, env_developers: env });
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

  const current = (await pgGetDevelopers().catch(() => null)) ?? [];
  if (current.includes(employeeNo)) return json({ error: 'already_developer' }, 409);
  const saved = await pgSetDevelopers([...current, employeeNo]);
  if (!saved) return json({ error: 'credential_store_unavailable', hint: 'PG 不可用，未持久化' }, 503);
  invalidateDeveloperCache();
  logAudit({ actor: getSession(request)?.subject ?? 'admin', action: 'developer:add', resource_type: 'system', resource_id: employeeNo });
  return json({ ok: true, employeeNo }, 201);
}

export async function DELETE(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const url = new URL(request.url);
  const employeeNo = (url.searchParams.get('employeeNo') ?? '').trim();
  if (!employeeNo) return json({ error: 'missing_employee_no' }, 400);

  const current = (await pgGetDevelopers().catch(() => null)) ?? [];
  if (!current.includes(employeeNo)) return json({ error: 'not_found' }, 404);
  const saved = await pgSetDevelopers(current.filter((s) => s !== employeeNo));
  if (!saved) return json({ error: 'credential_store_unavailable' }, 503);
  invalidateDeveloperCache();
  logAudit({ actor: getSession(request)?.subject ?? 'admin', action: 'developer:remove', resource_type: 'system', resource_id: employeeNo });
  return json({ ok: true, employeeNo });
}
