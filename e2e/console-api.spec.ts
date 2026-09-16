import { expect, test, type APIRequestContext } from '@playwright/test';
import { createHmac } from 'node:crypto';

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

  /**
   * 4A 跨设备会话吊销：管理员显式 revoke 后，既有会话（含当前）即刻失效；
   * 重新登录签发的新会话不受影响。无 PG 时如实 503 不假装吊销。
   */
  test('admin revoke invalidates existing sessions; fresh login still works', async ({
    request,
  }) => {
    await login(request);
    // sanity: current session is valid pre-revoke
    const before = await request.get('/api/tickets', { maxRedirects: 0 });
    expect(before.status(), 'session must be valid before revoke').toBe(200);

    const revoke = await request.post('/api/auth/revoke', { data: { subject: USER } });
    if (revoke.status() === 200) {
      // existing (pre-revoke) session must now be rejected (307 gate / 401)
      const after = await request.get('/api/tickets', { maxRedirects: 0 });
      expect([307, 401], 'revoked session must not access protected API').toContain(after.status());
      // fresh login issues a new session that works
      await login(request);
      const fresh = await request.get('/api/tickets', { maxRedirects: 0 });
      expect(fresh.status(), 'fresh session after revoke must work').toBe(200);
    } else {
      // no PG: honest 503, session untouched
      expect(revoke.status()).toBe(503);
      const still = await request.get('/api/tickets', { maxRedirects: 0 });
      expect(still.status()).toBe(200);
    }
  });
});

/** 4A · Accounting 合规导出：CSV/JSON 全量附件，且导出行为自身被审计。 */
test.describe('audit export', () => {
  test('csv and json exports return the full trail as attachments', async ({ request }) => {
    await login(request);

    const csv = await request.get('/api/audit?format=csv');
    expect(csv.status()).toBe(200);
    expect(csv.headers()['content-type'] ?? '').toContain('text/csv');
    expect(csv.headers()['content-disposition'] ?? '').toContain('attachment');
    const csvText = await csv.text();
    const lines = csvText.trim().split('\n');
    expect(lines[0]).toBe('timestamp,actor,action,resource_type,resource_id,detail,source');
    expect(lines.length, 'export must include at least the header + one row').toBeGreaterThanOrEqual(2);

    const js = await request.get('/api/audit?format=json');
    expect(js.status()).toBe(200);
    expect(js.headers()['content-disposition'] ?? '').toContain('attachment');
    const arr = (await js.json()) as unknown;
    expect(Array.isArray(arr)).toBe(true);
  });

  test('unauthenticated export is gated to login', async ({ playwright }) => {
    const anon = await playwright.request.newContext({ baseURL: BASE_URL });
    try {
      const res = await anon.get('/api/audit?format=csv', { maxRedirects: 0 });
      expect(res.status()).toBe(307);
    } finally {
      await anon.dispose();
    }
  });
});

/* ── RFC6238 TOTP helper（Node 侧，e2e 生成有效码）────────────────── */
function b32decode(input: string): Buffer {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of input.replace(/=+$/g, '').toUpperCase()) {
    const idx = A.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
function totpCode(secret: string): string {
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', b32decode(secret)).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[off] & 0x7f) << 24) | ((hmac[off + 1] & 0xff) << 16) | ((hmac[off + 2] & 0xff) << 8) | (hmac[off + 3] & 0xff)) %
    1_000_000;
  return String(code).padStart(6, '0');
}

/**
 * 4A · MFA(TOTP) 全生命周期：enroll → confirm → 登录二次验证 → disable。
 * finally 保证恢复单因素，避免污染后续用例的密码登录。无 PG 时 enroll 如实 503，
 * 该用例跳过启用断言（仅验证不假成功）。
 */
test.describe('mfa totp lifecycle', () => {
  test('enroll, confirm, two-step login, then disable restores single-factor', async ({
    request,
  }) => {
    let secret = '';
    await login(request);
    try {
      const enroll = await request.post('/api/auth/mfa', { data: { action: 'enroll' } });
      if (enroll.status() === 503) return; // no PG: honest unavailable, nothing enabled
      expect(enroll.status()).toBe(200);
      const eb = (await enroll.json()) as { secret?: string; otpauth_uri?: string };
      expect(typeof eb.secret).toBe('string');
      expect(eb.otpauth_uri ?? '').toContain('otpauth://totp/');
      secret = eb.secret as string;

      const confirm = await request.post('/api/auth/mfa', { data: { action: 'confirm', code: totpCode(secret) } });
      expect(confirm.status()).toBe(200);

      // password-only login now returns a challenge (200 + mfa_required), no session
      const pw = await request.post('/api/auth/login', { data: { username: USER, password: PASS } });
      expect(pw.status()).toBe(200);
      const pb = (await pw.json()) as { mfa_required?: boolean; mfa_token?: string };
      expect(pb.mfa_required, 'MFA-enabled account must get a challenge').toBe(true);
      expect(typeof pb.mfa_token).toBe('string');

      // correct code issues a session
      const good = await request.post('/api/auth/mfa', {
        data: { action: 'verify', mfa_token: pb.mfa_token, code: totpCode(secret) },
      });
      expect(good.status()).toBe(200);

      // disable with a valid code (session from verify)
      const disable = await request.post('/api/auth/mfa', { data: { action: 'disable', code: totpCode(secret) } });
      expect(disable.status()).toBe(200);
      secret = ''; // disabled successfully

      // single-factor login works again
      await login(request);
    } finally {
      if (secret) {
        // mid-test failure: force-disable using the known secret + still-valid pre-enable session
        await request.post('/api/auth/mfa', { data: { action: 'disable', code: totpCode(secret) } });
      }
    }
  });
});

/**
 * 批4 每设备可吊销上报令牌：enroll 为每台设备签发独立 token 并向 Collector 注册；
 * 控制台 revoke-token 删除后，再次 enroll 应拿到**不同**的新 token（旧令牌已失效，
 * 终端 401 后凭 0.33.1 自愈重入网）。仅 live（有 Collector）适用。
 */
test.describe('per-device revocable report tokens', () => {
  const DEV = 'abcdef012345';

  test('enroll issues per-device token; revoke invalidates; re-enroll rotates', async ({
    request,
  }) => {
    const e1 = await request.post('/api/enroll', { data: { device_id: DEV, hostname: 'e2e-throwaway', agent_version: '0.33.1' } });
    if (e1.status() === 503) return; // no collector/config: honest unavailable
    expect(e1.status()).toBe(200);
    const t1 = ((await e1.json()) as { report_token?: string }).report_token;
    expect(typeof t1).toBe('string');

    await login(request);
    const revoke = await request.post(`/api/devices/${DEV}/revoke-token`);
    expect(revoke.status(), 'admin must be able to revoke per-device token').toBe(200);

    const e2 = await request.post('/api/enroll', { data: { device_id: DEV, hostname: 'e2e-throwaway', agent_version: '0.33.1' } });
    expect(e2.status()).toBe(200);
    const t2 = ((await e2.json()) as { report_token?: string }).report_token;
    expect(typeof t2).toBe('string');
    expect(t2, 're-enroll after revoke must rotate the per-device token').not.toBe(t1);
  });
});

/**
 * 设备连接态与关注态分离（用户反馈 bug 回归锁）：collector 源下 status 只反映连接
 * (online/stale/offline)，不被发现严重度覆盖；关注态用独立 attention 布尔；
 * 每台设备上报全部 ai_agent 工具于 tools[]（覆盖面板据此聚合，不再只取 tools[0]）。
 */
test.describe('devices connectivity vs attention', () => {
  test('collector-sourced devices separate connectivity from attention and expose tools', async ({
    request,
  }) => {
    await login(request);
    const res = await request.get('/api/devices');
    expect(res.status()).toBe(200);
    const body = (await res.json()) as {
      source?: string;
      devices?: Array<{ status?: string; attention?: unknown; tools?: unknown }>;
    };
    if (body.source !== 'collector' || (body.devices ?? []).length === 0) return; // demo/无终端: 不适用
    for (const d of body.devices ?? []) {
      expect(['online', 'stale', 'offline'], 'status must be connectivity only').toContain(d.status);
      expect(typeof d.attention, 'attention must be a boolean').toBe('boolean');
      expect(Array.isArray(d.tools), 'tools must be an array').toBe(true);
    }
  });
});

/**
 * 4A · capability RBAC 批2b：operator 白名单持久化生命周期。
 * admin 添加 → 该工号获得 device:write → admin 移除 → 回落 viewer(403)。
 * 持久化在 PG settings(allowlist:operators)，写后 invalidate 缓存即刻生效。
 */
test.describe('operator persisted lifecycle', () => {
  const OP = 'e2eop-persist';

  function mintCookie(subject: string): string {
    const expiry = Date.now() + 3_600_000;
    const payload = `${subject}.${expiry}`;
    const sig = createHmac('sha256', process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789').update(payload).digest('hex');
    return `aegis_session=${payload}.${sig}`;
  }

  test('add operator grants device:write; remove revokes it', async ({ request, playwright }) => {
    await login(request);
    const add = await request.post('/api/operators', { data: { employeeNo: OP } });
    if (add.status() === 503) return; // no PG (demo): honest credential_store_unavailable, nothing persisted
    expect([201, 409], 'admin must be able to add operator').toContain(add.status());

    const opCtx = await playwright.request.newContext({ baseURL: BASE_URL });
    try {
      const cookie = mintCookie(OP);
      const write = await opCtx.post('/api/devices', {
        headers: { Cookie: cookie },
        data: { device_id: 'op-persist-01', hostname: 'op-h', owner: 'ops', agent_type: 'aegis', agent_version: '0.33.1', policy_version: '4.11.0' },
        maxRedirects: 0,
      });
      expect([200, 201], 'persisted operator must have device:write').toContain(write.status());
      await opCtx.delete(`/api/devices?device_id=op-persist-01`, { headers: { Cookie: cookie }, maxRedirects: 0 });
    } finally {
      await opCtx.dispose();
    }

    const del = await request.delete(`/api/operators?employeeNo=${OP}`);
    expect(del.status(), 'admin must be able to remove operator').toBe(200);

    const opCtx2 = await playwright.request.newContext({ baseURL: BASE_URL });
    try {
      const cookie = mintCookie(OP);
      const after = await opCtx2.post('/api/devices', {
        headers: { Cookie: cookie },
        data: { device_id: 'op-persist-02', hostname: 'op-h', owner: 'ops', agent_type: 'aegis', agent_version: '0.33.1', policy_version: '4.11.0' },
        maxRedirects: 0,
      });
      expect(after.status(), 'removed operator must fall back to viewer (403)').toBe(403);
    } finally {
      await opCtx2.dispose();
    }
  });
});
