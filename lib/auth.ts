/**
 * lib/auth.ts — session + RBAC for the Aegis console.
 *
 * Roles:
 *  - admin:  local admin account OR employee numbers in AEGIS_ADMIN_USERS.
 *            Full read + mutation.
 *  - viewer: any other UAC-authenticated identity. Read-only; mutations 403.
 *
 * Role is derived SERVER-SIDE from the session subject against the admin
 * allowlist on EVERY request — never trusted from a cookie.
 */
import { NextResponse } from 'next/server';

export type Role = 'admin' | 'viewer';

export interface Session {
  subject: string; // username (local) or employeeNo (UAC)
  role: Role;
}

export function adminAllowlist(): Set<string> {
  const raw = process.env.AEGIS_ADMIN_USERS ?? '';
  const set = new Set<string>(['admin']); // local admin always admin
  for (const part of raw.split(',')) {
    const v = part.trim();
    if (v) set.add(v);
  }
  return set;
}

/** Parse the aegis_session cookie payload `subject[.role].expiry.sig`. */
export function parseSession(cookieValue: string | undefined): Session | null {
  if (!cookieValue) return null;
  const parts = cookieValue.split('.');
  // payload = subject.expiry  (subject may itself contain no '.')
  if (parts.length < 3) return null;
  const expiry = Number(parts[parts.length - 2]);
  if (!Number.isFinite(expiry) || expiry < Date.now()) return null;
  const subject = parts.slice(0, parts.length - 2).join('.');
  if (!subject) return null;
  const role: Role = adminAllowlist().has(subject) ? 'admin' : 'viewer';
  return { subject, role };
}

export function getSession(request: Request): Session | null {
  const cookie = request.headers.get('cookie') ?? '';
  const match = cookie.match(/(?:^|;\s*)aegis_session=([^;]+)/);
  return parseSession(match ? decodeURIComponent(match[1]) : undefined);
}

/** 403 response for viewers attempting mutations. */
export function forbidden(): NextResponse {
  return NextResponse.json(
    { error: 'forbidden', hint: '只读身份无权限执行变更；如需权限请联系管理员加入 AEGIS_ADMIN_USERS' },
    { status: 403 },
  );
}

/** Require admin; returns null if admin, else a 403 Response. */
export function requireAdmin(request: Request): NextResponse | null {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  if (session.role !== 'admin') return forbidden();
  return null;
}
