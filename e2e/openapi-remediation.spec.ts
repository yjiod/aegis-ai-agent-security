import { expect, test, type Page } from '@playwright/test';

/**
 * 绝对要求 #2（全量 API 预留）+ #3（全自动纠偏）e2e：
 * - /api/openapi 输出 OpenAPI 3.1 契约（登录态），含全部路径与 x-reserved 预留桩；
 * - 预留桩 /api/integrations/{health,events,...} 未登录被会话闸拦（health 公开 501）；
 * - 自动纠偏配置 GET/PUT 往返 + 审计；POST /api/remediation/auto-sweep 鉴权（未登录 401/307）。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';
const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

async function authedPage(page: Page) {
  const res = await page.request.post('/api/auth/login', {
    data: { username: USER, password: PASS },
  });
  expect(res.status()).toBe(200);
  const setCookie = res
    .headersArray()
    .find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('aegis_session='));
  expect(setCookie).toBeTruthy();
  const value = setCookie!.value.split(';')[0].slice('aegis_session='.length);
  await page.context().addCookies([{ name: 'aegis_session', value, url: BASE_URL }]);
}

test('openapi contract served and covers reserved stubs', async ({ page }) => {
  await authedPage(page);
  const res = await page.request.get('/api/openapi');
  expect(res.status()).toBe(200);
  const doc = (await res.json()) as {
    openapi: string;
    paths: Record<string, Record<string, { 'x-reserved'?: boolean }>>;
  };
  expect(doc.openapi).toBe('3.1.0');
  expect(Object.keys(doc.paths).length).toBeGreaterThanOrEqual(55);
  // 预留桩带 x-reserved 标记
  // 契约 paths 相对 servers.url=/api
  for (const stub of ['/integrations/health', '/integrations/events', '/integrations/inventory', '/integrations/subscribe', '/integrations/remediate']) {
    expect(doc.paths[stub], `${stub} must be in contract`).toBeTruthy();
    expect(Object.values(doc.paths[stub]).some((op) => op['x-reserved'] === true), `${stub} must be x-reserved`).toBe(true);
  }
});

test('reserved stubs return 501 with stable contract body', async ({ page }) => {
  await authedPage(page);
  const res = await page.request.post('/api/integrations/events');
  expect(res.status()).toBe(501);
  const body = (await res.json()) as { schema?: string; error?: string; reserved?: boolean };
  expect(body.schema).toBe('aegis.integration/v1');
  expect(body.error).toBe('not_implemented');
  expect(body.reserved).toBe(true);
});

test('remediation settings roundtrip and sweep auth', async ({ page }) => {
  await authedPage(page);
  const before = await page.request.get('/api/settings/remediation');
  expect(before.status()).toBe(200);
  const orig = ((await before.json()) as { config: { enabled: boolean; auto_deny: boolean; notify: boolean } }).config;
  // 写一个翻转值再写回（不依赖默认值）
  const put = await page.request.put('/api/settings/remediation', {
    data: { ...orig, notify: !orig.notify },
  });
  expect(put.status()).toBe(200);
  const flipped = ((await put.json()) as { config: { notify: boolean } }).config;
  expect(flipped.notify).toBe(!orig.notify);
  const back = await page.request.put('/api/settings/remediation', { data: orig });
  expect(back.status()).toBe(200);
  // 手动纠偏扫描可执行：live 模式（有 collector）ran=true；demo 模式诚实返回
  // ran=false + reason=collector_unconfigured（绝不伪造"已执行"）。
  const sweep = await page.request.post('/api/remediation/auto-sweep');
  expect(sweep.status()).toBe(200);
  const result = (await sweep.json()) as { ran?: boolean; reason?: string };
  expect(result.ran === true || result.reason === 'collector_unconfigured', `ran=${result.ran} reason=${result.reason}`).toBe(true);
});

test('openapi and remediation endpoints are session-gated', async ({ request }) => {
  // middleware 对未认证一律 307 跳 /login：禁止跟随重定向才能看到真实状态码。
  const r1 = await request.get('/api/openapi', { maxRedirects: 0 });
  expect([401, 307]).toContain(r1.status());
  const r2 = await request.post('/api/remediation/auto-sweep', { maxRedirects: 0 });
  expect([401, 307]).toContain(r2.status());
  const r3 = await request.put('/api/settings/remediation', { data: { enabled: false }, maxRedirects: 0 });
  expect([401, 307]).toContain(r3.status());
});

test('blocked sweep shows saved rules without claiming endpoint enforcement', async ({ page }) => {
  await authedPage(page);
  await page.route('**/api/remediation/auto-sweep', (route) => route.fulfill({
    json: {
      ran: true, findings: 1, denied: [{ asset_type: 'skill', asset_key: 'fixture-skill' }],
      conflicts: [], notified: 1, publish_blocked: 'blast_radius',
      status: { deny_rules: 'saved', policy: 'blocked', endpoint: 'unverified' },
    },
  }));
  await page.goto('/settings');
  await page.getByRole('button', { name: '立即执行一轮' }).click();
  const result = page.getByText('扫描 1 条发现 → 已保存拒绝规则 1 项', { exact: false });
  await expect(result).toBeVisible();
  await expect(result).toContainText('发布被拦截：blast_radius');
  await expect(result).toContainText('终端执行未验证');
  await expect(result).not.toContainText('已封禁');
  await expect(result).not.toContainText('策略已发布');
});
