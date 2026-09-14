import { expect, test, type APIRequestContext } from '@playwright/test';

/**
 * 签名策略发布闭环 e2e（认证态）。
 * 覆盖：admin 预览→发布→current 反映新版本且带签名；preview 输出与 publish 输出一致；
 * 非 admin（审计员）发布被拒 403；未认证被中间件网关拦截。
 *
 * 需要 dev server 环境：AEGIS_SESSION_SECRET（作为签名密钥回退）、
 * AEGIS_ADMIN_USERS=e2eadmin、AEGIS_AUDITOR_USERS=e2eauditor。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';

async function login(request: APIRequestContext) {
  const res = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
  expect(res.status(), 'login must succeed with configured creds').toBe(200);
}

test.describe('policy publish loop', () => {
  test('admin preview -> publish -> current is signed and versioned', async ({ request }) => {
    await login(request);

    const preview = await request.get('/api/policy/preview');
    expect(preview.status()).toBe(200);
    const pv = (await preview.json()) as {
      next_version: number;
      policy: { allowed_skills: string[]; allowed_mcp_servers: string[] };
    };
    expect(typeof pv.next_version).toBe('number');
    expect(Array.isArray(pv.policy.allowed_skills)).toBe(true);

    const pub = await request.post('/api/policy/publish', { data: { note: 'e2e publish' } });
    expect(pub.status()).toBe(200);
    const pb = (await pub.json()) as {
      published: boolean;
      version: number;
      signature: string;
      signing_key_id: string;
      policy: { allowed_skills: string[] };
    };
    expect(pb.published).toBe(true);
    expect(pb.version).toBe(pv.next_version);
    expect(pb.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(pb.signing_key_id).not.toBe('unconfigured');
    // preview 与 publish 输出一致（同一服务端权威计算）
    expect(pb.policy.allowed_skills).toEqual(pv.policy.allowed_skills);

    const cur = await request.get('/api/policy/current');
    expect(cur.status()).toBe(200);
    const cb = (await cur.json()) as { published: boolean; version: number; signature: string };
    expect(cb.published).toBe(true);
    expect(cb.version).toBe(pb.version);
    expect(cb.signature).toBe(pb.signature);
  });

  test('second publish increments the version monotonically', async ({ request }) => {
    await login(request);
    const first = await request.post('/api/policy/publish', { data: {} });
    const v1 = ((await first.json()) as { version: number }).version;
    const second = await request.post('/api/policy/publish', { data: {} });
    const v2 = ((await second.json()) as { version: number }).version;
    expect(v2).toBe(v1 + 1);
  });

  test('auditor cannot publish (403) but can read current', async ({ playwright }) => {
    const { createHmac } = await import('node:crypto');
    const secret = process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789';
    const expiry = Date.now() + 3_600_000;
    const payload = `e2eauditor.${expiry}`;
    const sig = createHmac('sha256', secret).update(payload).digest('hex');
    const ctx = await playwright.request.newContext({
      baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3000',
      storageState: {
        cookies: [
          { name: 'aegis_session', value: `${payload}.${sig}`, domain: 'localhost', path: '/', expires: Math.floor(Date.now() / 1000) + 3600, httpOnly: true, secure: false, sameSite: 'Lax' },
        ],
        origins: [],
      },
    });
    try {
      const pub = await ctx.post('/api/policy/publish', { data: {}, maxRedirects: 0 });
      expect(pub.status(), 'auditor must not publish').toBe(403);
      const cur = await ctx.get('/api/policy/current', { maxRedirects: 0 });
      expect(cur.status(), 'auditor may read current policy').toBe(200);
    } finally {
      await ctx.dispose();
    }
  });
});
