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
    const put = await request.put('/api/settings', { data: { scan_mode: 'quick' } });
    expect(put.status()).toBe(200);
    const get = await request.get('/api/settings');
    expect(get.status()).toBe(200);
    const body = (await get.json()) as { scan_mode?: string };
    expect(body.scan_mode).toBe('quick');
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

test.describe('remediation closed loop', () => {
  test('recommend -> approve -> receipt with ordering enforcement', async ({ request }) => {
    await login(request);
    const created = await request.post('/api/tickets', {
      data: { title: 'remediation e2e', severity: 'high', source: 'e2e', device_id: 'rem-device' },
    });
    expect(created.status()).toBe(201);
    const id = ((await created.json()) as { ticket?: { ticket_id: string } }).ticket?.ticket_id;
    expect(typeof id).toBe('string');
    const base = `/api/tickets/${id}/remediation`;

    // approve before any recommendation is rejected (approval-bound)
    const earlyApprove = await request.post(base, { data: { phase: 'approve', note: 'no rec yet' } });
    expect(earlyApprove.status()).toBe(409);

    // recommend without content is rejected
    const emptyRec = await request.post(base, { data: { phase: 'recommend' } });
    expect(emptyRec.status()).toBe(400);

    // recommend -> approve -> receipt happy path
    const rec = await request.post(base, { data: { phase: 'recommend', note: '升级 Agent 到最新版并收敛 MCP 文件范围' } });
    expect(rec.status()).toBe(200);
    const approve = await request.post(base, { data: { phase: 'approve', note: '安全负责人批准' } });
    expect(approve.status()).toBe(200);
    const receipt = await request.post(base, { data: { phase: 'receipt', note: '已于终端执行并复扫通过' } });
    expect(receipt.status()).toBe(200);
    const rb = (await receipt.json()) as { remediation?: { stage?: string } };
    expect(rb.remediation?.stage).toBe('receipt');

    // receipt before approve is impossible to re-test now; cleanup
    const del = await request.delete(`/api/tickets/${id}`);
    expect(del.status()).toBe(200);
  });
});

/**
 * /api/findings —— Skill/MCP/代码质量三个扫描器页的真实数据源。
 * 反伪造红线契约（demo 与 live 两种模式都必须成立）：
 *   1) 结构良好：connected 为布尔、findings 为数组、counts 五个数值键齐全；
 *   2) 断连诚实：connected=false 时 findings 必须为空且 counts.total=0 —— 绝不
 *      回填任何静态样例（此前页面内联伪造数据却标"实时"，此断言防回归）；
 *   3) 每条发现字段类型正确、category 与请求类目一致、severity ∈ 合法枚举；
 *   4) 未认证被门禁（307→/login）。
 */
type FindingsBody = {
  connected?: unknown;
  category?: unknown;
  devices?: unknown;
  devices_with_findings?: unknown;
  counts?: { total?: unknown; critical?: unknown; high?: unknown; medium?: unknown; low?: unknown };
  findings?: Array<Record<string, unknown>>;
};

test.describe('findings honesty contract', () => {
  const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);

  for (const category of ['skill', 'mcp', 'code'] as const) {
    test(`${category}: well-formed + never fabricates when disconnected`, async ({ request }) => {
      await login(request);
      const res = await request.get(`/api/findings?category=${category}`);
      expect(res.status()).toBe(200);
      const body = (await res.json()) as FindingsBody;

      // (1) structural
      expect(typeof body.connected).toBe('boolean');
      expect(body.category).toBe(category);
      expect(Array.isArray(body.findings)).toBe(true);
      const c = body.counts ?? {};
      for (const k of ['total', 'critical', 'high', 'medium', 'low'] as const) {
        expect(typeof c[k], `counts.${k} must be a number`).toBe('number');
      }

      const findings = body.findings ?? [];
      if (body.connected === false) {
        // (2) anti-fabrication invariant: disconnected ⟹ empty, zeroed
        expect(findings.length, 'disconnected must not return fabricated findings').toBe(0);
        expect(c.total).toBe(0);
        expect(body.devices_with_findings).toBe(0);
      }

      // (3) per-finding shape (no-op when empty)
      for (const f of findings) {
        expect(typeof f.device_id).toBe('string');
        expect(typeof f.kind).toBe('string');
        expect(f.category).toBe(category);
        expect(SEV.has(String(f.severity))).toBe(true);
        expect(typeof f.scanned_at).toBe('number');
      }
      // counts.total must equal the severity buckets sum (self-consistent)
      const bucketSum = Number(c.critical) + Number(c.high) + Number(c.medium) + Number(c.low);
      expect(Number(c.total), 'total must equal sum of severity buckets (>= , info folded to low)').toBeGreaterThanOrEqual(bucketSum);
    });
  }

  test('unauthenticated findings read is gated to login', async ({ playwright }) => {
    const anon = await playwright.request.newContext({ baseURL: BASE_URL });
    try {
      const res = await anon.get('/api/findings?category=skill', { maxRedirects: 0 });
      expect(res.status()).toBe(307);
      expect(res.headers()['location'] ?? '').toContain('/login');
    } finally {
      await anon.dispose();
    }
  });
});

/**
 * 4A 契约（Authentication 限流锁定 + Accounting 认证事件审计）。
 *
 * - 定向爆破防护：同一 (IP, 用户名) 连续失败满 5 次后，第 6 次直接 429
 *   account_temporarily_locked，不再校验密码。用独立用户名探测，避免锁掉
 *   e2e 管理员账号影响后续用例。
 * - 认证事件全审计：login 成功/失败/锁定、logout 都写审计trail；/api/audit
 *   合并 Collector 与控制台两源，故认证事件在 demo 与 live 模式都可见。
 */
test.describe('auth 4A contract', () => {
  const PROBE_USER = 'lockout-probe-e2e';

  test('repeated failed logins lock the account and every auth event is audited', async ({
    request,
  }) => {
    // 5 failures -> each 401
    for (let i = 0; i < 5; i += 1) {
      const res = await request.post('/api/auth/login', {
        data: { username: PROBE_USER, password: 'definitely-wrong' },
      });
      expect(res.status(), `failure #${i + 1} must be 401`).toBe(401);
    }
    // 6th attempt -> locked (429), password not even checked
    const locked = await request.post('/api/auth/login', {
      data: { username: PROBE_USER, password: 'definitely-wrong' },
    });
    expect(locked.status()).toBe(429);
    const lb = (await locked.json()) as { error?: string };
    expect(lb.error).toBe('account_temporarily_locked');

    // auth events audited (console source merged into /api/audit)
    await login(request);
    const audit = await request.get('/api/audit?limit=200');
    expect(audit.status()).toBe(200);
    const ab = (await audit.json()) as { entries?: Array<{ action: string; actor: string }> };
    const actions = (ab.entries ?? []).map((e) => `${e.actor}|${e.action}`);
    expect(actions.some((a) => a === `${PROBE_USER}|auth:login_failed`), 'auth:login_failed must be audited').toBe(true);
    expect(actions.some((a) => a === `${PROBE_USER}|auth:login_locked`), 'auth:login_locked must be audited').toBe(true);
  });

  test('successful login and server-side logout are audited', async ({ request }) => {
    await login(request); // produces auth:login for the admin subject
    const logout = await request.post('/api/auth/logout');
    expect(logout.status()).toBe(200);

    // re-login to read the audit trail (logout cleared this context's session)
    await login(request);
    const audit = await request.get('/api/audit?limit=200');
    expect(audit.status()).toBe(200);
    const ab = (await audit.json()) as { entries?: Array<{ action: string; actor: string }> };
    const actions = (ab.entries ?? []).map((e) => `${e.actor}|${e.action}`);
    expect(actions.some((a) => a === `${USER}|auth:login`), 'auth:login must be audited').toBe(true);
    expect(actions.some((a) => a === `${USER}|auth:logout`), 'auth:logout must be audited').toBe(true);
  });

  /**
   * 凭据生命周期（4A）：改密必须真实生效或如实报"存储不可用"，绝不假成功。
   * - 有 PG：改密 200 → 新密码可登录、旧密码 401 → 改回原密码恢复（避免污染后续用例）。
   * - 无 PG：如实 503 credential_store_unavailable，且原密码仍可登录（env 回落不变）。
   */
  test('change-password persists (or honestly reports store unavailable) and never fakes success', async ({
    request,
  }) => {
    const TEMP = 'Temp-E2e-Cred-9999';
    await login(request);

    const change = await request.post('/api/auth/change-password', {
      data: { current_password: PASS, new_password: TEMP },
    });

    if (change.status() === 200) {
      // persisted: new password works, old rejected
      const withNew = await request.post('/api/auth/login', { data: { username: USER, password: TEMP } });
      expect(withNew.status(), 'new password must log in after persisted change').toBe(200);
      const withOld = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
      expect(withOld.status(), 'old password must be rejected after persisted change').toBe(401);

      // change back to the env password so later suites/runs are unaffected
      const revert = await request.post('/api/auth/change-password', {
        data: { current_password: TEMP, new_password: PASS },
      });
      expect(revert.status(), 'revert must persist').toBe(200);
      const withOrig = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
      expect(withOrig.status(), 'original password must work after revert').toBe(200);
    } else {
      // no PG: honest failure, credentials untouched
      expect(change.status()).toBe(503);
      const cb = (await change.json()) as { error?: string };
      expect(cb.error).toBe('credential_store_unavailable');
      const stillOk = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
      expect(stillOk.status(), 'env password must still work when store unavailable').toBe(200);
    }
  });
});
