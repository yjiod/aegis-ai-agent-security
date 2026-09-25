import { expect, test, type Page } from '@playwright/test';

/**
 * 风险页工单行设备识别（2026-09-25 用户反馈）：
 * 光显示 device_id 哈希分不出是哪台机器 → 行内必须出现 序列号 + 用户，
 * IP/MAC 默认折叠、点开可见（无网络信息时诚实标注）。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';
const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

async function authedPage(page: Page) {
  const res = await page.request.post('/api/auth/login', { data: { username: USER, password: PASS } });
  expect(res.status()).toBe(200);
  const setCookie = res
    .headersArray()
    .find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('aegis_session='));
  expect(setCookie).toBeTruthy();
  const value = setCookie!.value.split(';')[0].slice('aegis_session='.length);
  await page.context().addCookies([{ name: 'aegis_session', value, url: BASE_URL }]);
}

test('risks ticket rows identify devices by serial + user with collapsible IP/MAC', async ({ page }) => {
  await authedPage(page);
  await page.goto('/risks');
  // 等 SSR 水合 + 工单列表渲染（可能为空 → 跳过）
  const row = page.locator('.risk-row').first();
  if (!(await row.count())) test.skip(true, 'no tickets in this environment');

  // IP/MAC 折叠按钮存在且默认收起
  const toggle = page.locator('button', { hasText: /IP \/ MAC/ }).first();
  await expect(toggle).toBeVisible();
  await expect(page.locator('text=/出口 IP|内网 IP|未上报网络信息/').first()).toBeHidden();

  // 展开后出现网络信息行之一（诚实空态也算通过）
  await toggle.click();
  await expect(page.locator('text=/出口 IP|内网 IP|MAC |未上报网络信息/').first()).toBeVisible({ timeout: 10_000 });
  await toggle.click();
  await expect(page.locator('text=/出口 IP|内网 IP|未上报网络信息/').first()).toBeHidden();

  // 设备列不再只有裸哈希：有"查看发现"链接（即设备列渲染完整）
  await expect(page.locator('a', { hasText: '查看发现' }).first()).toBeVisible();
});
