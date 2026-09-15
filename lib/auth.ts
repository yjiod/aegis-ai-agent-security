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
import { pgGetSessionRevocations } from '@/lib/pg-store';

export type Role = 'admin' | 'operator' | 'auditor' | 'viewer';

export interface Session {
  subject: string; // username (local) or employeeNo (UAC)
  role: Role;
}

/** 会话寿命（与 login/oidc/uac 签发 expiry = now + 7d 保持一致）。 */
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/* ── 4A · 跨设备会话吊销 ───────────────────────────────────────────
 * parseSession 是同步热路径（每个受保护请求都调），不能在其中做 PG I/O。
 * 故用模块级缓存（30s TTL）持有 {subject -> invalid_before}，由 middleware
 * 每请求异步预热（refreshSessionRevocations）。同步查询只读缓存：
 *   - 缓存未命中/PG 不可用 → 返回 0（不吊销，fail-open 保可用性）；
 *   - 吊销生效延迟 ≤ TTL（30s），对"改密/移除/显式吊销"足够。
 */
const REVOCATION_TTL_MS = 30_000;
let revocationCache: { at: number; map: Map<string, number> } | null = null;

export async function refreshSessionRevocations(): Promise<void> {
  if (revocationCache && Date.now() - revocationCache.at < REVOCATION_TTL_MS) return;
  const data = await pgGetSessionRevocations();
  if (data === null) return; // PG 不可用：保留旧缓存（fail-open）
  revocationCache = { at: Date.now(), map: new Map(Object.entries(data)) };
}

/** 同步读取某 subject 的会话失效时间戳（0 = 无吊销记录）。 */
export function sessionRevokedBefore(subject: string): number {
  return revocationCache?.map.get(subject) ?? 0;
}

/** 记录一次吊销（改密/移除白名单/显式吊销调用），并立即刷新本地缓存使其即刻生效。 */
export async function revokeSessions(subject: string): Promise<boolean> {
  const { pgSetSessionRevocation } = await import('@/lib/pg-store');
  const ok = await pgSetSessionRevocation(subject, Date.now());
  if (ok) revocationCache = null; // 失效缓存，下次读取重新加载
  return ok;
}

/* ── 会话签发（login 与 mfa/verify 共用，保证 Cookie 语义一致）────── */

/** 签发 aegis_session token（subject.expiry.sig，expiry=now+7d）。 */
export async function signSessionToken(subject: string): Promise<string> {
  const secret = sessionSecrets()[0];
  if (!secret) throw new Error('no session secret configured');
  const expiry = Date.now() + SESSION_TTL_MS;
  const payload = `${subject}.${expiry}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${payload}.${sigHex}`;
}

/** 把已签发的 token 挂到响应 Cookie（httpOnly/secure/lax/7d）。 */
export function attachSessionCookie(
  response: { cookies: { set: (name: string, value: string, opts: Record<string, unknown>) => void } },
  token: string,
): void {
  response.cookies.set('aegis_session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS / 1000,
  });
}

/* ── 4A · MFA 挑战令牌（短期、绑定 subject）──────────────────────────
 * 密码通过后若该 subject 已启用 TOTP，不直接发会话，而是下发 5 分钟有效的
 * mfa.<subject>.<expiry>.<sig> 挑战；mfa/verify 校验 TOTP 码后才签发会话。
 * 复用 sessionSecrets/verifySessionSignature，无需新密钥管理。
 */
const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;

export function issueMfaToken(subject: string): string {
  const secret = sessionSecrets()[0];
  if (!secret) return '';
  const expiry = Date.now() + MFA_TOKEN_TTL_MS;
  const payload = `mfa.${subject}.${expiry}`;
  const sig = createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

/** 校验挑战令牌，返回绑定的 subject；无效/过期/篡改返回 null。 */
export function verifyMfaToken(token: string): string | null {
  const parts = (token ?? '').split('.');
  if (parts.length < 4 || parts[0] !== 'mfa') return null;
  const expiry = Number(parts[parts.length - 2]);
  if (!Number.isFinite(expiry) || expiry < Date.now()) return null;
  const subject = parts.slice(1, parts.length - 2).join('.');
  if (!subject) return null;
  const signedPayload = parts.slice(0, parts.length - 1).join('.');
  if (!verifySessionSignature(signedPayload, parts[parts.length - 1])) return null;
  return subject;
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

/**
 * Operator 白名单（运维工程师档，4A 最小权限）：env AEGIS_OPERATOR_USERS ∪ 持久化
 * （settings 表 allowlist:operators）。持久化部分经 middleware 预热的内存缓存同步读取
 * （roleForSubject 是同步热路径）；写操作 invalidate 缓存使其下次请求生效。
 * fail-closed：env 与持久化皆空即无 operator。
 */
const OPERATOR_CACHE_TTL_MS = 60_000;
let operatorCache: { at: number; list: string[] } | null = null;

export async function refreshOperators(): Promise<void> {
  if (operatorCache && Date.now() - operatorCache.at < OPERATOR_CACHE_TTL_MS) return;
  const { pgGetOperators } = await import('@/lib/pg-store');
  const list = await pgGetOperators();
  if (list === null) return; // PG 不可用：保留旧缓存（fail-open 读、不扩权）
  operatorCache = { at: Date.now(), list };
}

export function invalidateOperatorCache(): void {
  operatorCache = null;
}

export function operatorAllowlist(): Set<string> {
  const set = new Set<string>();
  for (const part of (process.env.AEGIS_OPERATOR_USERS ?? '').split(',')) {
    const v = part.trim();
    if (v) set.add(v);
  }
  for (const v of operatorCache?.list ?? []) set.add(v);
  return set;
}

/** Resolve a subject to its highest-privilege role (admin > operator > auditor > viewer). */
export function roleForSubject(subject: string): Role {
  if (adminAllowlist().has(subject)) return 'admin';
  if (operatorAllowlist().has(subject)) return 'operator';
  if (auditorAllowlist().has(subject)) return 'auditor';
  return 'viewer';
}

/** 终端写权限：admin 或 operator（4A capability 门禁）。 */
export function canWriteDevices(role: Role | null | undefined): boolean {
  return role === 'admin' || role === 'operator';
}

/** 设备写门禁：未认证 401；无 device:write 能力 403。 */
export function requireDeviceWriter(request: Request): NextResponse | null {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  if (!canWriteDevices(session.role)) return forbidden();
  return null;
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
  // 4A 会话吊销：签发时间(expiry-7d)早于该 subject 的 invalid_before 即失效。
  const issued = expiry - SESSION_TTL_MS;
  if (issued < sessionRevokedBefore(subject)) return null;
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
