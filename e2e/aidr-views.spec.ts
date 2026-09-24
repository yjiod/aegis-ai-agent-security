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
    // 覆盖计数如实呈现；AGT06/07/LLM09 已由新规则覆盖（不再恒为缺口）
    await expect(page.locator('text=/覆盖 \\d+\\/\\d+/').first()).toBeVisible();
    await expect(page.locator('text=LLM01 / AGT01').first()).toBeVisible();
    await expect(page.locator('text=Skill·prompt_override').first()).toBeVisible();
    await expect(page.locator('text=AGT06').first()).toBeVisible();
    await expect(page.locator('text=Skill·context_poisoning').first()).toBeVisible();
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

  test('ticket drawer shows 响应闭环 (detection -> asset -> disposition) section', async ({ page }) => {
    await authedPage(page);
    await page.goto('/risks');
    // 有工单才可测；空队列(demo 无 PG)时跳过——绝不为测而造数据。
    const row = page.locator('.risk-row').first();
    if (!(await row.count())) {
      test.skip(true, 'no tickets available for the D&R loop drawer test');
      return;
    }
    await row.click();
    const drawer = page.locator('[data-slot="drawer-content"], [class*="drawer"]').first();
    await expect(drawer).toBeVisible({ timeout: 15_000 });
    // 抽屉包含 响应闭环 与 响应 Playbook 两个 AIDR 段
    await expect(page.locator('text=响应闭环').first()).toBeVisible();
    await expect(page.locator('text=响应 Playbook').first()).toBeVisible();
    // 闭环段三行 kv：检测规则 / 关联资产 / 当前处置
    await expect(page.locator('text=当前处置').first()).toBeVisible();
    await expect(page.locator('text=关联资产').first()).toBeVisible();
    // 处置状态必须是三态语义（加白/观察/拉黑/未处置）或解析中——不得空白
    const disposition = page.locator('text=/加白|观察|拉黑|未处置|解析中/').first();
    await expect(disposition).toBeVisible({ timeout: 15_000 });
  });
});
