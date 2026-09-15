import { NextResponse } from 'next/server';
import { logAudit } from '@/lib/store';
import { loadPasswordHash, verifyPassword } from '@/lib/credentials';
import { issueMfaToken, signSessionToken, attachSessionCookie } from '@/lib/auth';
import { pgGetMfa } from '@/lib/pg-store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

/* ── 4A · Authentication：登录限流 + 失败锁定 ─────────────────────
 * 凭据端点是唯一可被暴力穷举的入口，必须限流。两层（单 workerd 实例内
 * best-effort，与 /api/enroll 同款思路）：
 *   1) 每 IP 每分钟最多 LOGIN_RATE_PER_MIN 次尝试——挡高频扫描/撞库。取值需
 *      高于合法峰值（含自动化 e2e 的密集登录），真正的定向爆破由第 2 层拦；
 *   2) 每 (IP, 用户名) 在 LOCK_WINDOW 内失败满 LOCK_MAX 次即锁定余下时间，
 *      直接 429 不再校验密码——挡针对单账号的在线穷举。
 * 所有成功/失败/锁定都写审计（4A · Accounting），actor 为尝试的用户名。
 */
const LOGIN_RATE_PER_MIN = 60;
const RATE_WINDOW_MS = 60_000;
const LOCK_MAX = 5;
const LOCK_WINDOW_MS = 15 * 60_000;

const attempts = new Map<string, number[]>(); // ip -> timestamps (rate)
const failures = new Map<string, number[]>(); // ip|user -> failure timestamps (lock)

function prune(arr: number[], windowMs: number, now: number): number[] {
  return arr.filter((t) => now - t < windowMs);
}

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const arr = prune(attempts.get(ip) ?? [], RATE_WINDOW_MS, now);
  arr.push(now);
  attempts.set(ip, arr);
  if (attempts.size > 5000) for (const [k, v] of attempts) if (v.length === 0) attempts.delete(k);
  return arr.length > LOGIN_RATE_PER_MIN;
}

function lockedOut(key: string): boolean {
  const now = Date.now();
  const arr = prune(failures.get(key) ?? [], LOCK_WINDOW_MS, now);
  failures.set(key, arr);
  return arr.length >= LOCK_MAX;
}

function recordFailure(key: string) {
  const now = Date.now();
  const arr = prune(failures.get(key) ?? [], LOCK_WINDOW_MS, now);
  arr.push(now);
  failures.set(key, arr);
}

function clearFailures(key: string) {
  failures.delete(key);
}

function clientIp(request: Request): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

/** 审计 actor/资源 ID 有界化，避免把超长或恶意输入写进审计 trail。 */
function bounded(value: string, max = 64): string {
  return value.slice(0, max);
}

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Validates against AEGIS_CONSOLE_USER / AEGIS_CONSOLE_PASSWORD env vars.
 * On success sets an HMAC-signed session cookie (7 day expiry).
 * 4A：限流/锁定 + 全量认证事件审计（成功/失败/锁定）。
 */
export async function POST(request: Request) {
  const ip = clientIp(request);

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const username = bounded(String(body.username ?? '').trim());
  const password = String(body.password ?? '');
  const lockKey = `${ip}|${username}`;

  if (rateLimited(ip)) {
    logAudit({ actor: username || 'anonymous', action: 'auth:login_rate_limited', resource_type: 'system', detail: `ip=${bounded(ip)}` });
    return json({ error: 'rate_limited', hint: '登录尝试过于频繁，请稍后再试' }, 429);
  }

  if (lockedOut(lockKey)) {
    logAudit({ actor: username || 'anonymous', action: 'auth:login_locked', resource_type: 'system', detail: `ip=${bounded(ip)} failures>=${LOCK_MAX}` });
    return json({ error: 'account_temporarily_locked', hint: `失败次数过多，请 ${Math.ceil(LOCK_WINDOW_MS / 60000)} 分钟后再试` }, 429);
  }

  const expectedUser = process.env.AEGIS_CONSOLE_USER ?? 'admin';
  const expectedPass = process.env.AEGIS_CONSOLE_PASSWORD ?? '';
  // 4A 凭据生命周期：优先校验持久化哈希（改密后生效）；无哈希（未改过密或 PG
  // 不可用）回落 env。fail-safe：PG 不可用不锁死既有登录。
  const persistedHash = await loadPasswordHash(expectedUser);

  if (!persistedHash && !expectedPass) {
    return json({ error: 'auth_not_configured', hint: 'Set AEGIS_CONSOLE_PASSWORD on the server' }, 503);
  }

  // Constant-time comparison
  const userOk = username.length === expectedUser.length &&
    username.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedUser.charCodeAt(i)), 0) === 0;
  let passOk = false;
  if (userOk) {
    if (persistedHash) {
      passOk = await verifyPassword(password, persistedHash);
    } else {
      passOk = password.length === expectedPass.length &&
        password.split('').reduce((acc, c, i) => acc | (c.charCodeAt(0) ^ expectedPass.charCodeAt(i)), 0) === 0;
    }
  }

  if (!userOk || !passOk) {
    recordFailure(lockKey);
    logAudit({ actor: username || 'anonymous', action: 'auth:login_failed', resource_type: 'system', detail: `ip=${bounded(ip)} reason=invalid_credentials` });
    return json({ error: 'invalid_credentials' }, 401);
  }

  clearFailures(lockKey);

  // 4A · MFA：已启用 TOTP 的账号，密码通过后不直接发会话，改为下发 5 分钟挑战令牌；
  // 客户端提交有效 TOTP 码（POST /api/auth/mfa/verify）后才签发会话。未启用 MFA 的
  // 账号行为不变（直接发会话），故默认不影响既有登录与 e2e。
  const mfa = await pgGetMfa(username).catch(() => null);
  if (mfa?.enabled) {
    logAudit({ actor: username, action: 'auth:mfa_challenge', resource_type: 'system', detail: `ip=${bounded(ip)}` });
    return json({ mfa_required: true, mfa_token: issueMfaToken(username) });
  }

  logAudit({ actor: username, action: 'auth:login', resource_type: 'system', detail: `ip=${bounded(ip)} method=local` });
  const token = await signSessionToken(username);
  const response = json({ ok: true, username, expiry: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  attachSessionCookie(response, token);
  return response;
}

/** GET /api/auth/login — check current session */
export async function GET() {
  return json({ authenticated: false, hint: 'POST to login' }, 401);
}
