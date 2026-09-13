/**
 * lib/auth.ts — session + RBAC for the Aegis console.
 *
 * Roles (highest privilege first):
 *  - admin:   local admin account OR employee numbers in AEGIS_ADMIN_USERS /
 *             the persisted admin allowlist. Full read + mutation + user mgmt.
 *  - auditor: employee numbers in AEGIS_AUDITOR_USERS / the persisted auditor
 *             allowlist. Read-only, but privileged enough to read the audit
 *             trail and the admin/auditor rosters (compliance review). Cannot
 *             mutate anything — every write returns 403.
 *  - viewer:  any other authenticated identity. Dashboard/device/ticket read
 *             only; NO access to the sensitive audit trail or user rosters;
 *             mutations 403.
 *
 * Role is derived SERVER-SIDE from the session subject against the allowlists
 * on EVERY request — never trusted from a cookie.
 */
import { NextResponse } from 'next/server';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { getAdminStore, getAuditorStore } from '@/lib/store';

export type Role = 'admin' | 'auditor' | 'viewer';

export interface Session {
  subject: string; // username (local) or employeeNo (UAC)
  role: Role;
}

/**
 * Ordered, de-duplicated candidate HMAC secrets used by the three session
 * issuers. All three prefer AEGIS_SESSION_SECRET; each has a provider-specific
 * fallback for when it is unset:
 *   - local login : AEGIS_SESSION_SECRET ?? AEGIS_CONSOLE_PASSWORD
 *   - oidc        : AEGIS_SESSION_SECRET ?? AEGIS_OIDC_CLIENT_SECRET
 *   - uac         : AEGIS_SESSION_SECRET ?? AEGIS_UAC_APP_ID
 * Verification tries each candidate so a session signed by any issuer validates.
 */
function sessionSecrets(): string[] {
  const candidates = [
    process.env.AEGIS_SESSION_SECRET,
    process.env.AEGIS_CONSOLE_PASSWORD,
    process.env.AEGIS_OIDC_CLIENT_SECRET,
    process.env.AEGIS_UAC_APP_ID,
  ];
  const out: string[] = [];
  for (const c of candidates) {
    if (c && !out.includes(c)) out.push(c);
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Constant-time verify the HMAC-SHA256 signature over `signedPayload`. Returns
 * false (fail closed) when no secret is configured or the signature is malformed
 * or does not match — this is what makes the cookie unforgeable and the RBAC
 * role derivation trustworthy (a viewer cannot hand-craft an admin cookie).
 */
export function verifySessionSignature(signedPayload: string, sigHex: string): boolean {
  const provided = hexToBytes(sigHex);
  if (!provided) return false;
  const secrets = sessionSecrets();
  if (secrets.length === 0) return false;
  for (const secret of secrets) {
    const digest = new Uint8Array(createHmac('sha256', secret).update(signedPayload).digest());
    if (digest.length === provided.length && timingSafeEqual(digest, provided)) return true;
  }
  return false;
}

function allowlistFrom(envValue: string | undefined, persisted: string[], base: string[] = []): Set<string> {
  const set = new Set<string>(base);
  for (const p of persisted) set.add(p);
  for (const part of (envValue ?? '').split(',')) {
    const v = part.trim();
    if (v) set.add(v);
  }
  return set;
}

export function adminAllowlist(): Set<string> {
  // merge env allowlist + persisted admins (SSO admin management)
  // local admin account is always an admin.
  let persisted: string[] = [];
  try {
    persisted = getAdminStore();
  } catch { /* store unavailable */ }
  return allowlistFrom(process.env.AEGIS_ADMIN_USERS, persisted, ['admin']);
}

/** Auditor allowlist: env AEGIS_AUDITOR_USERS + persisted auditors. */
export function auditorAllowlist(): Set<string> {
  let persisted: string[] = [];
  try {
    persisted = getAuditorStore();
  } catch { /* store unavailable */ }
  return allowlistFrom(process.env.AEGIS_AUDITOR_USERS, persisted);
}

/** Resolve a subject to its highest-privilege role (admin > auditor > viewer). */
export function roleForSubject(subject: string): Role {
  if (adminAllowlist().has(subject)) return 'admin';
  if (auditorAllowlist().has(subject)) return 'auditor';
  return 'viewer';
}

/** Parse and cryptographically verify the aegis_session cookie `subject.expiry.sig`. */
export function parseSession(cookieValue: string | undefined): Session | null {
  if (!cookieValue) return null;
  const parts = cookieValue.split('.');
  // payload = subject.expiry  (subject may itself contain no '.')
  if (parts.length < 3) return null;
  const expiry = Number(parts[parts.length - 2]);
  if (!Number.isFinite(expiry) || expiry < Date.now()) return null;
  const subject = parts.slice(0, parts.length - 2).join('.');
  if (!subject) return null;
  // Reject forged/tampered cookies: the signature must match our HMAC secret.
  const signedPayload = parts.slice(0, parts.length - 1).join('.');
  const sigHex = parts[parts.length - 1];
  if (!verifySessionSignature(signedPayload, sigHex)) return null;
  return { subject, role: roleForSubject(subject) };
}

export function getSession(request: Request): Session | null {
  const cookie = request.headers.get('cookie') ?? '';
  const match = cookie.match(/(?:^|;\s*)aegis_session=([^;]+)/);
  return parseSession(match ? decodeURIComponent(match[1]) : undefined);
}

/** 403 response for read-only identities (viewer/auditor) attempting mutations. */
export function forbidden(): NextResponse {
  return NextResponse.json(
    { error: 'forbidden', hint: '只读身份无权限执行变更；如需管理权限请联系管理员加入 AEGIS_ADMIN_USERS，仅需查阅审计可加入 AEGIS_AUDITOR_USERS' },
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

/**
 * Require admin OR auditor; returns null if allowed to read privileged/audit
 * data, a 401 when unauthenticated, else a 403. Auditors get read access to the
 * audit trail and user rosters but never mutation rights.
 */
export function requireAuditor(request: Request): NextResponse | null {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  if (session.role !== 'admin' && session.role !== 'auditor') return forbidden();
  return null;
}

/** True when the session may read the audit trail (admin or auditor). */
export function canReadAudit(session: Session | null): boolean {
  return session?.role === 'admin' || session?.role === 'auditor';
}
