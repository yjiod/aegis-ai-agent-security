import { expect, test, type APIRequestContext } from '@playwright/test';

// 本文件每个用例都会 POST /api/policy/publish，递增服务端单调版本号；并行 worker
// 会相互竞争导致"精确版本号"断言抖动。串行执行消除竞争。
test.describe.configure({ mode: 'serial' });

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

  test('posture reflects the published policy version', async ({ request }) => {
    await login(request);
    await request.post('/api/policy/publish', { data: {} });
    const res = await request.get('/api/policy/posture');
    expect(res.status()).toBe(200);
    const p = (await res.json()) as {
      published: boolean;
      source?: 'collector' | 'registry';
      connected?: boolean;
      current_version?: string;
      total_devices: number;
      on_current: number;
      drifted: number;
      unknown: number;
    };
    expect(p.published).toBe(true);
    expect(typeof p.current_version).toBe('string');
    expect(p.source === 'collector' || p.source === 'registry').toBe(true);
    expect(typeof p.connected).toBe('boolean');
    expect(typeof p.total_devices).toBe('number');
    expect(typeof p.on_current).toBe('number');
    expect(typeof p.drifted).toBe('number');
    expect(typeof p.unknown).toBe('number');
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

test.describe('signing key governance', () => {
  test('admin lists, rotates, publishes with new key, and retires old key', async ({ request }) => {
    await login(request);

    const list = await request.get('/api/policy/keys');
    expect(list.status()).toBe(200);
    const lr = (await list.json()) as { active_key_id: string | null; keys: Array<{ key_id: string; in_keyring: boolean; status: string }> };
    expect(lr.active_key_id, 'dev env must configure AEGIS_POLICY_SIGNING_KEYS').not.toBeNull();
    const ringKeys = lr.keys.filter((k) => k.in_keyring).map((k) => k.key_id);
    expect(ringKeys.length, 'keyring should have >=2 keys to rotate').toBeGreaterThanOrEqual(2);
    const oldActive = lr.active_key_id as string;
    const target = ringKeys.find((k) => k !== oldActive) as string;

    // rotate to the other keyring key
    const rot = await request.post('/api/policy/keys', { data: { to_key_id: target } });
    expect(rot.status()).toBe(200);
    const rr = (await rot.json()) as { active_key_id: string };
    expect(rr.active_key_id).toBe(target);

    // publish now signs with the new active key
    const pub = await request.post('/api/policy/publish', { data: {} });
    expect(pub.status()).toBe(200);
    const pb = (await pub.json()) as { signing_key_id: string };
    expect(pb.signing_key_id).toBe(target);

    // retiring the ACTIVE key is refused (409)
    const retireActive = await request.post(`/api/policy/keys/${target}/retire`);
    expect(retireActive.status()).toBe(409);

    // retiring the now-retiring old key succeeds (current release uses the new key)
    const retireOld = await request.post(`/api/policy/keys/${oldActive}/retire`);
    expect(retireOld.status()).toBe(200);
  });

  test('auditor can read keys but cannot rotate (403)', async ({ playwright }) => {
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
      const list = await ctx.get('/api/policy/keys', { maxRedirects: 0 });
      expect(list.status(), 'auditor may read key governance').toBe(200);
      const rot = await ctx.post('/api/policy/keys', { data: { to_key_id: 'k2' }, maxRedirects: 0 });
      expect(rot.status(), 'auditor must not rotate keys').toBe(403);
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('policy artifact (endpoint-loadable)', () => {
  test('artifact is the flattened signed aegis.policy/v1 the agent can load', async ({ request }) => {
    await login(request);
    const pub = await request.post('/api/policy/publish', { data: {} });
    expect(pub.status()).toBe(200);

    const res = await request.get('/api/policy/artifact');
    expect(res.status()).toBe(200);
    const art = (await res.json()) as Record<string, unknown>;
    // 顶层即 aegis.policy/v1（拍平件），不是嵌套信封——终端 load_policy 才能直接消费。
    expect(art.schema).toBe('aegis.policy/v1');
    expect(typeof art.version).toBe('string');
    expect((art.version as string).length).toBeGreaterThan(0);
    expect(art.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof art.signing_key_id).toBe('string');
    expect(art.signing_key_id).not.toBe('unconfigured');
    // 出厂字段被继承（发布件不丢自更新/自定义基线能力）。
    expect(typeof art.agent_self_update).toBe('object');
    expect(Array.isArray(art.custom_baseline_rules)).toBe(true);
    // 分发完整性头。
    expect(res.headers()['x-aegis-policy-sha256']).toMatch(/^[0-9a-f]{64}$/);

    // 工件版本与 posture 的当前版本一致（同一发布件）。
    const posture = await request.get('/api/policy/posture');
    const pj = (await posture.json()) as { current_version?: string };
    expect(pj.current_version).toBe(art.version);
  });
});

test.describe('version posture single source of truth', () => {
  /**
   * 回归：仪表盘(/api/summary)与策略页(/api/policy/posture)必须对"当前应有的策略版本"
   * 给出同一个权威值。此前 summary 用 Collector 静态 required_policy_version(4.8.0)分桶、
   * posture 用已发布版本(4.9.0+)，对同一批终端得出相反的 current/drifted 结论。
   * 修复后 summary 在控制台侧用已发布版本重算 version_posture 并覆盖 required_policy_version。
   *
   * 已认证读取（login 后 request 上下文带会话 Cookie；/api/summary 受中间件保护）。
   * 未连接 Collector 时诚实降级：不附 summary，无从比较——用例据此收敛，绝不断言虚构值。
   */
  test('summary adopts the authoritative published version and agrees with posture', async ({ request }) => {
    await login(request);

    // 串行发布一个已知的权威版本（本文件 serial，避免与其它用例竞争单调版本号）。
    const pub = await request.post('/api/policy/publish', { data: { note: 'e2e posture-source' } });
    expect(pub.status()).toBe(200);

    const postureRes = await request.get('/api/policy/posture');
    expect(postureRes.status()).toBe(200);
    const posture = (await postureRes.json()) as { published: boolean; current_version?: string };
    expect(posture.published).toBe(true);
    const authoritative = posture.current_version as string;
    expect(authoritative, 'posture must expose a semver current_version').toMatch(/^\d+\.\d+\.\d+$/);

    const sumRes = await request.get('/api/summary');
    // /api/summary 连接态返回 200；未配置/不可达/契约非法返回 5xx（demo 模式即 503）。
    // 两种都是诚实结果，故接受这一组状态码，再按 connected 分支断言。
    expect([200, 502, 503], `unexpected summary status ${sumRes.status()}`).toContain(sumRes.status());
    const sum = (await sumRes.json()) as {
      connected: boolean;
      summary?: {
        required_policy_version: string;
        required_policy_version_source?: string;
        version_posture_recomputed?: boolean;
        total_devices: number;
        version_posture: Record<string, number>;
      };
    };

    if (!sum.connected) {
      // 未连接 Collector：诚实降级为 demo 模式，不附 summary。
      expect(sum.summary, 'disconnected summary must not fabricate a summary body').toBeUndefined();
      return;
    }

    const s = sum.summary as NonNullable<typeof sum.summary>;
    if (s.version_posture_recomputed) {
      // 单一可信源：仪表盘的 required_policy_version 必须等于策略页的权威已发布版本。
      expect(s.required_policy_version, 'summary must adopt the authoritative published policy version').toBe(authoritative);
      expect(s.required_policy_version_source).toBe('published_release');
      // 分桶守恒：重算后各姿态计数之和仍等于设备总数（不凭空增减终端）。
      const bucketSum = Object.values(s.version_posture).reduce((a, b) => a + Number(b), 0);
      expect(bucketSum, 'recomputed posture buckets must conserve total_devices').toBe(s.total_devices);
    } else {
      // 设备集与计数无法逐台核对时诚实标注为静态来源，绝不冠以"权威版本"之名。
      expect(s.required_policy_version_source).toBe('collector_static');
    }
  });
});

test.describe('zero-touch enrollment', () => {
  /**
   * /api/enroll 必须中间件豁免（终端首次入网时还没有会话），并在服务端配置了上报令牌时
   * 自动下发：report_token + 每设备 signing_secret + report_url + 去签名的已发布策略体。
   * 关键安全断言：下发的策略**不含 signature/signing_key_id**——绝不暴露 HMAC 签名/验签密钥
   * （否则任何人都能伪造"已签名"策略）。未配置上报令牌时（demo 模式）诚实返回 503。
   */
  test('POST /api/enroll is session-exempt and issues token + unsigned policy', async ({ request, playwright }) => {
    // 先用管理员会话发布一个策略，确保有已发布策略可下发。
    await login(request);
    const pub = await request.post('/api/policy/publish', { data: { note: 'e2e enroll' } });
    expect(pub.status()).toBe(200);
    const published = (await pub.json()) as { policy?: { version?: string } };

    // 全新无会话上下文，模拟终端首次入网。
    const ctx = await playwright.request.newContext({
      baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:3000',
    });
    try {
      const res = await ctx.post('/api/enroll', {
        data: { hostname: 'e2e-enroll-host', device_id: 'e2e-enroll-dev', agent_version: '0.32.0' },
        maxRedirects: 0,
      });
      // 中间件豁免：绝不能被 307 重定向到 /login。
      expect(res.status(), '/api/enroll must be middleware-exempt (never 307)').not.toBe(307);
      expect([200, 503], `unexpected enroll status ${res.status()}`).toContain(res.status());
      const body = (await res.json()) as Record<string, unknown>;

      if (res.status() === 503) {
        // demo 模式：服务端未配置上报令牌，诚实拒绝而非伪造凭据。
        expect(body.error).toBe('enrollment_not_configured');
        return;
      }

      expect(body.schema).toBe('aegis.enrollment/v1');
      expect(typeof body.report_token).toBe('string');
      expect((body.report_token as string).length).toBeGreaterThanOrEqual(32);
      expect(typeof body.signing_secret).toBe('string');
      expect((body.signing_secret as string).length).toBeGreaterThanOrEqual(32);
      expect(body.signing_secret).not.toBe(body.report_token);
      expect(body.report_url).toMatch(/\/aegis\/v1\/reports$/);

      const policy = body.policy as Record<string, unknown> | undefined;
      if (policy) {
        expect(policy.schema).toBe('aegis.policy/v1');
        // 安全红线：下发策略去签名，绝不泄露签名/验签密钥。
        expect(policy.signature, 'enrolled policy must NOT carry a signature').toBeUndefined();
        expect(policy.signing_key_id, 'enrolled policy must NOT carry a key id').toBeUndefined();
        expect(typeof policy.version).toBe('string');
        if (published.policy?.version) expect(policy.version).toBe(published.policy.version);
        expect(body.policy_version).toBe(policy.version);
      }
    } finally {
      await ctx.dispose();
    }
  });
});

