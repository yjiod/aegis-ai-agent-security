import { expect, test, request as pwRequest, type APIRequestContext } from '@playwright/test';
import { createHmac } from 'node:crypto';

/**
 * RBAC + 会话签名 e2e。
 *
 * 三级角色: admin(全权) / auditor(只读+可查审计) / viewer(只读, 不可查审计)。
 * 角色由服务端根据 subject 命中 AEGIS_ADMIN_USERS / AEGIS_AUDITOR_USERS 推导,
 * 且会话 cookie 必须通过 HMAC-SHA256 签名校验(伪造签名 => 视为未认证)。
 *
 * 本地登录只支持单个控制台账号(admin), 因此 auditor / viewer / 伪造 cookie 用
 * 已知 AEGIS_SESSION_SECRET 直接构造合法(或非法)签名会话来驱动 —— 这与三个
 * 签发方(local/oidc/uac)使用同一套 HMAC 机制, 属于对生产鉴权路径的真实覆盖。
 *
 * 需要的 dev server 环境:
 *   AEGIS_SESSION_SECRET, AEGIS_ADMIN_USERS=e2eadmin, AEGIS_AUDITOR_USERS=e2eauditor
 */

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;
const SECRET = process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789';

const ADMIN = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const AUDITOR = process.env.E2E_AUDITOR_USER ?? 'e2eauditor';
const VIEWER = 'e2eviewer'; // 不在任何白名单 => viewer

/** 构造一个合法签名的 aegis_session cookie 值: `subject.expiry.sigHex`。 */
function signedCookie(subject: string, expiry = Date.now() + 3_600_000): string {
  const payload = `${subject}.${expiry}`;
  const sig = createHmac('sha256', SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

/** 构造一个签名被篡改(伪造)的 cookie 值: subject/expiry 合法但 sig 错误。 */
function forgedCookie(subject: string, expiry = Date.now() + 3_600_000): string {
  const payload = `${subject}.${expiry}`;
  const badSig = 'f'.repeat(64);
  return `${payload}.${badSig}`;
}

const COOKIE_DOMAIN = new URL(BASE_URL).hostname;

// Playwright's APIRequestContext manages its own cookie jar and drops a manual
// `cookie` extraHeader, so the session cookie must be injected via storageState.
async function ctxWithCookie(cookieValue: string): Promise<APIRequestContext> {
  return pwRequest.newContext({
    baseURL: BASE_URL,
    storageState: {
      cookies: [
        {
          name: 'aegis_session',
          value: cookieValue,
          domain: COOKIE_DOMAIN,
          path: '/',
          expires: Math.floor(Date.now() / 1000) + 3600,
          httpOnly: true,
          secure: false,
          sameSite: 'Lax',
        },
      ],
      origins: [],
    },
  });
}

test.describe('RBAC: auditor (read-only, audit-visible)', () => {
  test('auditor can read audit trail and admin roster', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const audit = await ctx.get('/api/audit?limit=5', { maxRedirects: 0 });
      expect(audit.status(), 'auditor must read /api/audit').toBe(200);
      const admins = await ctx.get('/api/admins', { maxRedirects: 0 });
      expect(admins.status(), 'auditor must read /api/admins').toBe(200);
      const auditors = await ctx.get('/api/auditors', { maxRedirects: 0 });
      expect(auditors.status()).toBe(200);
    } finally {
      await ctx.dispose();
    }
  });

  test('auditor cannot mutate (tickets/settings/admins all 403)', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const t = await ctx.post('/api/tickets', {
        data: { title: 'nope', severity: 'high', source: 'e2e', device_id: 'd1' },
        maxRedirects: 0,
      });
      expect(t.status(), 'auditor POST /api/tickets must be 403').toBe(403);

      const s = await ctx.put('/api/settings', { data: { scan_mode: 'quick' }, maxRedirects: 0 });
      expect(s.status(), 'auditor PUT /api/settings must be 403').toBe(403);

      const a = await ctx.post('/api/admins', { data: { employeeNo: 'hacker01' }, maxRedirects: 0 });
      expect(a.status(), 'auditor POST /api/admins must be 403').toBe(403);

      const au = await ctx.post('/api/auditors', { data: { employeeNo: 'hacker02' }, maxRedirects: 0 });
      expect(au.status(), 'auditor POST /api/auditors must be 403').toBe(403);
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('RBAC: viewer (read-only, no audit)', () => {
  test('viewer is denied the audit trail and rosters (403)', async () => {
    const ctx = await ctxWithCookie(signedCookie(VIEWER));
    try {
      const audit = await ctx.get('/api/audit?limit=5', { maxRedirects: 0 });
      expect(audit.status(), 'viewer must NOT read /api/audit').toBe(403);
      const admins = await ctx.get('/api/admins', { maxRedirects: 0 });
      expect(admins.status(), 'viewer must NOT read /api/admins').toBe(403);
    } finally {
      await ctx.dispose();
    }
  });

  test('viewer cannot mutate (403)', async () => {
    const ctx = await ctxWithCookie(signedCookie(VIEWER));
    try {
      const t = await ctx.post('/api/tickets', {
        data: { title: 'nope', severity: 'high', source: 'e2e', device_id: 'd1' },
        maxRedirects: 0,
      });
      expect(t.status()).toBe(403);
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('RBAC: admin', () => {
  test('admin can read audit and mutate', async () => {
    const ctx = await ctxWithCookie(signedCookie(ADMIN));
    try {
      const audit = await ctx.get('/api/audit?limit=5', { maxRedirects: 0 });
      expect(audit.status()).toBe(200);
      const created = await ctx.post('/api/tickets', {
        data: { title: 'rbac admin ticket', severity: 'low', source: 'e2e', device_id: 'rbac-admin' },
        maxRedirects: 0,
      });
      expect(created.status()).toBe(201);
      const body = (await created.json()) as { ticket?: { ticket_id: string } };
      const id = body.ticket?.ticket_id;
      if (id) await ctx.delete(`/api/tickets/${id}`, { maxRedirects: 0 });
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('session signature verification', () => {
  test('forged admin cookie is rejected (not treated as admin)', async () => {
    const ctx = await ctxWithCookie(forgedCookie(ADMIN));
    try {
      // Middleware sees a cookie (presence+expiry) so it does NOT 307 to /login,
      // but the route-level HMAC verification fails => getSession() === null =>
      // requireAdmin returns 401. A forged cookie must never grant admin.
      const t = await ctx.post('/api/tickets', {
        data: { title: 'forged', severity: 'high', source: 'e2e', device_id: 'd1' },
        maxRedirects: 0,
      });
      expect(t.status(), 'forged cookie must not mutate').toBe(401);

      const audit = await ctx.get('/api/audit?limit=5', { maxRedirects: 0 });
      expect(audit.status(), 'forged cookie must not read audit').toBe(401);
    } finally {
      await ctx.dispose();
    }
  });

  test('tampered subject with valid-looking sig is rejected', async () => {
    // Sign for viewer, then swap the subject to admin without re-signing.
    const expiry = Date.now() + 3_600_000;
    const viewerSig = createHmac('sha256', SECRET).update(`${VIEWER}.${expiry}`).digest('hex');
    const tampered = `${ADMIN}.${expiry}.${viewerSig}`;
    const ctx = await ctxWithCookie(tampered);
    try {
      const t = await ctx.post('/api/tickets', {
        data: { title: 'tampered', severity: 'high', source: 'e2e', device_id: 'd1' },
        maxRedirects: 0,
      });
      expect(t.status(), 'subject swap must break the signature => 401').toBe(401);
    } finally {
      await ctx.dispose();
    }
  });
});
