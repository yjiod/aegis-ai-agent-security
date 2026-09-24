import { expect, test, type Page } from '@playwright/test';

/**
 * 处置中心规模化 UI 回归（2026-09-25 用户反馈）：
 * 1) AI Agent 预制库（数百项）展开后必须是「搜索 + 类型筛选 + 分页」，
 *    一次只渲染一页（20 项），绝不整列平铺；
 * 2) 签名策略发布预览不得把全量加白名单堆成一屏文字：
 *    预制库完全不进明细，自定义处置按类分组只显示计数，
 *    名字藏在「明细（分页）」折叠里。
 *
 * 前置：seed-defaults 已入库（run-e2e 环境由 console-api 的 seed 用例保证；
 * 此处对 0 项环境自动跳过，避免假红）。
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

/** 预制库面板（含标题徽标的那个 panel）。 */
function presetPanel(page: Page) {
  return page.locator('div.panel', { hasText: 'AI Agent 预制库' }).first();
}

test('dispositions: preset library expands to paginated + filterable view, not a wall', async ({ page }) => {
  await authedPage(page);
  await page.goto('/dispositions');
  const toggle = page.locator('button', { hasText: '展开查看 / 单独覆盖' });
  await toggle.waitFor({ state: 'visible', timeout: 20_000 }).catch(() => {});
  if (!(await toggle.isVisible())) test.skip(true, 'no preset labels seeded');
  await toggle.click();
  const panel = presetPanel(page);
  // 搜索框 + 类型筛选存在
  await expect(panel.locator('input[placeholder*="预制库"]')).toBeVisible();
  await expect(panel.locator('select').first()).toBeVisible();
  // 一次只渲染一页：行内「系统默认」徽标 ≤ 20（防御数百项平铺回归；标题徽标文本
  // 是"AI Agent 预制库 · 系统默认放行 N 项"，不会命中 exact 匹配）
  const rows = panel.locator('text="系统默认"');
  const count = await rows.count();
  expect(count, 'one page must render at most 20 rows').toBeLessThanOrEqual(20);
  // 分页器出现且可翻页
  const pager = panel.locator('button', { hasText: '下一页' }).first();
  await expect(pager).toBeVisible();
  await pager.click();
  await expect(panel.locator('text=/第 2 \\/ \\d+ 页/')).toBeVisible();
  // 搜索收窄：命中项直接一页放完，翻页按钮隐藏（不再需要翻页）
  await panel.locator('input[placeholder*="预制库"]').fill('xlsx');
  await expect(panel.locator('button', { hasText: '下一页' })).toBeHidden();
  await expect(rows.first()).toBeVisible();
});

test('dispositions: policy publish preview groups custom decisions instead of dumping full lists', async ({ page }) => {
  await authedPage(page);
  // 自备一条自定义处置，保证「明细（分页）」入口存在（e2e 库可能无任何自定义项）
  const E2E_KEY = 'e2e-ui-breakdown-skill';
  const put = await page.request.post('/api/labels', {
    data: { asset_type: 'skill', asset_key: E2E_KEY, disposition: 'allow', tags: ['e2e'] },
  });
  expect(put.status(), 'seed one custom label for breakdown assertions').toBeLessThan(400);
  await page.goto('/dispositions');
  try {
    const heading = page.locator('h2', { hasText: '签名策略发布' });
    await expect(heading).toBeVisible({ timeout: 20_000 });
    const section = heading.locator('xpath=ancestor::div[contains(@class,"panel")]');
    // 服务端权威预览一行仍是计数摘要
    await expect(section.locator('text=/将编译 \\d+ 加白/')).toBeVisible({ timeout: 20_000 });
    // 不再出现平铺全量名单（旧版是 "加白 Skill：<几百个逗号拼接>"）
    expect(await section.locator('p:has-text("加白 Skill")').count(), 'no flat skill dump').toBe(0);
    expect(await section.locator('p:has-text("加白 MCP")').count(), 'no flat mcp dump').toBe(0);
    // 自定义处置归类行存在（计数徽标 + 明细（分页）入口）
    await expect(section.locator('text=自定义加白 Skill')).toBeVisible();
    const detailsBtn = section.locator('button', { hasText: '明细（分页）' }).first();
    await expect(detailsBtn).toBeVisible();
    // 点开明细：chip 化（能看到刚加的自定义项）+ 可收起
    await detailsBtn.click();
    await expect(section.locator('button', { hasText: '收起明细' }).first()).toBeVisible();
    await expect(section.locator('text="e2e-ui-breakdown-skill"').first()).toBeVisible();
    await section.locator('button', { hasText: '收起明细' }).first().click();
    await expect(section.locator('button', { hasText: '收起明细' })).toHaveCount(0);
  } finally {
    await page.request.delete(`/api/labels?asset_type=skill&asset_key=${encodeURIComponent(E2E_KEY)}`);
  }
});
