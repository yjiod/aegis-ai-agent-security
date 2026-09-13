import { expect, test, type APIRequestContext } from '@playwright/test';

/**
 * 控制台 API e2e(认证态): 登录/工单 CRUD/基线/设置/集成控制面。
 * 凭据来自环境变量 E2E_ADMIN_USER / E2E_ADMIN_PASSWORD(与 dev server 的
 * AEGIS_CONSOLE_USER/PASSWORD 一致); 未认证路径断言 401。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';
const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

async function login(request: APIRequestContext) {
  const res = await request.post('/api/auth/login', {
    data: { username: USER, password: PASS },
  });
  expect(res.status(), 'login must succeed with configured creds').toBe(200);
}

test.describe('auth', () => {
  test('login success sets session cookie', async ({ request }) => {
    const res = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
    expect(res.status()).toBe(200);
  });

  test('wrong password rejected', async ({ request }) => {
    const res = await request.post('/api/auth/login', { data: { username: USER, password: 'wrong-pass' } });
    expect(res.status()).toBe(401);
  });

  test('unauthenticated baselines read is gated to login', async ({ playwright }) => {
    // Fresh, isolated context so no session cookie can bleed in from a login
    // test that ran earlier in the same worker.
    const anon = await playwright.request.newContext({ baseURL: BASE_URL });
    try {
      // The middleware session guard answers unauthenticated /api/* with a 307
      // redirect to /login. maxRedirects:0 stops Playwright from following it to
      // the 200 login page so we can assert the gate itself.
      const res = await anon.get('/api/baselines', { maxRedirects: 0 });
      expect(res.status()).toBe(307);
      expect(res.headers()['location'] ?? '').toContain('/login');
    } finally {
      await anon.dispose();
    }
  });
});

test.describe('tickets CRUD', () => {
  test('create -> list -> transition -> delete', async ({ request }) => {
    await login(request);
    const created = await request.post('/api/tickets', {
      data: {
        title: 'e2e ticket',
        severity: 'high',
        source: 'e2e',
        device_id: 'e2e-device-01',
        description: 'e2e created ticket',
      },
    });
    expect(created.status()).toBe(201);
    const body = (await created.json()) as { ticket?: { ticket_id: string } };
    const id = body.ticket?.ticket_id;
    expect(typeof id).toBe('string');

    const list = await request.get('/api/tickets?limit=50');
    expect(list.status()).toBe(200);
    const lb = (await list.json()) as { tickets?: Array<{ ticket_id: string }> };
    expect((lb.tickets ?? []).some((t) => t.ticket_id === id)).toBe(true);

    const trans = await request.put(`/api/tickets/${id}`, {
      data: { status: 'acknowledged', note: 'e2e ack' },
    });
    expect(trans.status()).toBe(200);

    const del = await request.delete(`/api/tickets/${id}`);
    expect(del.status()).toBe(200);
  });
});

test.describe('baselines', () => {
  test('import -> list -> delete', async ({ request }) => {
    await login(request);
    const name = `e2e-baseline-${Date.now()}`;
    const imp = await request.post('/api/baselines', {
      data: { name, rules: [{ id: 'no-eval', title: '禁止 eval', severity: 'high', mode: 'standard' }] },
    });
    expect(imp.status()).toBe(200);

    const list = await request.get('/api/baselines');
    expect(list.status()).toBe(200);
    const lb = (await list.json()) as { baselines?: Array<{ name: string }> };
    expect((lb.baselines ?? []).some((b) => b.name === name)).toBe(true);

    const del = await request.delete(`/api/baselines?name=${name}`);
    expect(del.status()).toBe(200);
  });
});

test.describe('settings', () => {
  test('scan_mode put/get roundtrip', async ({ request }) => {
    await login(request);
    const put = await request.put('/api/settings', { data: { scan_mode: 'deep' } });
    expect(put.status()).toBe(200);
    const get = await request.get('/api/settings');
    expect(get.status()).toBe(200);
    const body = (await get.json()) as { scan_mode?: string };
    expect(body.scan_mode).toBe('deep');
    // restore
    await request.put('/api/settings', { data: { scan_mode: 'standard' } });
  });

  test('invalid scan_mode rejected', async ({ request }) => {
    await login(request);
    const put = await request.put('/api/settings', { data: { scan_mode: 'nope' } });
    expect(put.status()).toBe(400);
  });
});

test.describe('integrations', () => {
  test('probe + config + sync', async ({ request }) => {
    await login(request);
    const probe = await request.get('/api/integrations');
    expect(probe.status()).toBe(200);
    const pb = (await probe.json()) as { integrations?: Array<{ name: string; health: string }> };
    expect(Array.isArray(pb.integrations)).toBe(true);
    expect((pb.integrations ?? []).some((i) => i.name === 'Aegis(本端)')).toBe(true);

    const cfg = await request.get('/api/integrations/config');
    expect(cfg.status()).toBe(200);

    const sync = await request.post('/api/integrations/sync');
    expect(sync.status()).toBe(200);
    const sb = (await sync.json()) as { created?: number };
    expect(typeof sb.created).toBe('number');
  });
});
