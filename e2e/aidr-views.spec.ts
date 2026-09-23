import { expect, test, type Page } from '@playwright/test';

/**
 * AIDR 视图回归 e2e（认证态 UI）：锁定检测覆盖矩阵、风险中心统一筛选条 / 超 SLA。
 * 通过 API 登录注入 aegis_session cookie（避免 UI 登录水合抖动）；用「元素可见」
 * 作水合信号（dev server 长连接使 networkidle 永不收敛）。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';
const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

async function authedPage(page: Page) {
  const res = await page.request.post('/api/auth/login', {
    data: { username: USER, password: PASS },
  });
  expect(res.status(), 'login must succeed with configured creds').toBe(200);
  const setCookie = res
    .headersArray()
    .find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('aegis_session='));
  expect(setCookie, 'login must set aegis_session cookie').toBeTruthy();
  const value = setCookie!.value.split(';')[0].slice('aegis_session='.length);
  await page.context().addCookies([{ name: 'aegis_session', value, url: BASE_URL }]);
}

test.describe('aidr views', () => {
  test('engines shows detection-coverage matrix with honest gaps', async ({ page }) => {
    await authedPage(page);
    await page.goto('/engines');
    const panel = page.locator('text=检测覆盖 · 技战法映射').first();
    await expect(panel).toBeVisible({ timeout: 20_000 });
    // 覆盖计数 + 缺口如实标注（出厂基座下应有缺口，不伪装全覆盖）
    await expect(page.locator('text=/覆盖 \\d+\\/\\d+/').first()).toBeVisible();
    await expect(page.locator('text=/缺口 \\d+/').first()).toBeVisible();
    // 至少一条技战法行（LLM01 提示注入）与其覆盖规则徽章
    await expect(page.locator('text=LLM01 / AGT01').first()).toBeVisible();
    await expect(page.locator('text=Skill·prompt_override').first()).toBeVisible();
  });

  test('risks unified filter bar + 超SLA toggle behave', async ({ page }) => {
    await authedPage(page);
    await page.goto('/risks');
    const bar = page.locator('[role="toolbar"][aria-label="工单统一筛选"]');
    await expect(bar).toBeVisible({ timeout: 20_000 });
    await expect(bar.locator('select').first()).toBeVisible();
    await expect(bar.locator('button', { hasText: '超 SLA' })).toBeVisible();
    // 命中读数存在（空队列时为 命中 0 / 0 工单）
    await expect(page.locator('text=/命中 \\d+ \\/ \\d+ 工单/').first()).toBeVisible();
    // 超 SLA 开关可切换且 aria-pressed 反映状态。
    // 首屏 HTML 由 SSR 产出，"可见"不等于 onClick 已挂载：用有界轮询点击兜底水合竞态。
    const sla = bar.locator('button', { hasText: '超 SLA' });
    for (let i = 0; i < 10; i += 1) {
      await sla.click();
      if ((await sla.getAttribute('aria-pressed')) === 'true') break;
      await page.waitForTimeout(300);
    }
    await expect(sla).toHaveAttribute('aria-pressed', 'true');
    // 激活后出现清除筛选
    await expect(bar.locator('button', { hasText: '清除筛选' })).toBeVisible();
    await bar.locator('button', { hasText: '清除筛选' }).click();
    await expect(sla).toHaveAttribute('aria-pressed', 'false');
  });
});
