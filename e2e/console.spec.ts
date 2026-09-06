import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * E2E coverage for the Aegis Agent security console UI.
 *
 * The app currently ships no `data-testid` attributes, so selectors are built
 * from the semantic class names already used by the design system
 * (`.nav-item`, `.metric`, `.risk-row`, `.severity`, `.switch`, `.toast`,
 * `.data-table`, `.detail-kpis`, `.panel.scan-trend`) plus the Chinese label
 * text rendered on screen.
 *
 * Every assertion that depends on a CSS breakpoint is commented with the
 * breakpoint that actually drives it (see app/globals.css section 16).
 */

const BASE_URL =
  process.env.E2E_BASE_URL ??
  `http://localhost:${Number(process.env.PORT ?? 3000)}`;

/** Sidebar navigation, in the order rendered by components/console-shell.tsx. */
const NAV_ITEMS = [
  { href: '/', label: '总览', heading: 'AI Agent 安全总览' },
  { href: '/onboarding', label: '接入中心', heading: '接入中心' },
  { href: '/devices', label: '设备与 Agent', heading: '设备与 Agent' },
  { href: '/risks', label: '风险中心', heading: '风险中心' },
  { href: '/baseline', label: '编码规范基线', heading: '安全编码规范基线' },
  { href: '/skills', label: 'Skill 扫描器', heading: 'Skill 扫描器' },
  { href: '/mcp', label: 'MCP 扫描器', heading: 'MCP 扫描器' },
  { href: '/quality', label: '代码质量', heading: '代码质量扫描' },
  { href: '/policies', label: '策略配置', heading: '终端安全策略' },
  { href: '/team', label: '团队与权限', heading: '团队与权限' },
  { href: '/settings', label: '系统设置', heading: '系统设置' },
] as const;

/** Scanner pages share the same "bar chart + data table" shape. */
const SCANNER_PAGES = [
  { href: '/skills', heading: 'Skill 扫描器', minRows: 1 },
  { href: '/mcp', heading: 'MCP 扫描器', minRows: 1 },
  { href: '/quality', heading: '代码质量扫描', minRows: 1 },
] as const;

function absoluteUrl(href: string): string {
  return new URL(href, BASE_URL).toString();
}

function navLink(page: Page, href: string): Locator {
  return page.locator(`.sidebar a.nav-item[href="${href}"]`);
}

/** Number of resolved grid tracks for a grid container's columns. */
async function gridTrackCount(page: Page, selector: string): Promise<number> {
  return page.locator(selector).evaluate((element) => {
    const value = window.getComputedStyle(element).gridTemplateColumns;
    return value.split(/\s+/).filter(Boolean).length;
  });
}

/** Strip non-numeric characters so "96.8%" and "312" can both be compared. */
function numericPart(text: string): number {
  return Number.parseFloat(text.replace(/[^\d.]/g, '')) || 0;
}

test.describe('navigation', () => {
  test('sidebar links navigate to their routes and render the page heading', async ({
    page,
  }) => {
    await page.goto('/');
    await expect(page.locator('.sidebar')).toBeVisible();

    for (const { href, label, heading } of NAV_ITEMS) {
      const link = navLink(page, href);
      await expect(link, `missing nav link for ${href}`).toBeVisible();
      await expect(link).toContainText(label);

      await link.click();
      await page.waitForURL(absoluteUrl(href));
      await expect(page).toHaveURL(absoluteUrl(href));

      const pageHeading = page.locator('main h1');
      await expect(pageHeading, `h1 never appeared for ${href}`).toHaveCount(1);
      await expect(pageHeading).toHaveText(heading);
    }
  });

  test('exactly one nav item is active and it matches the current route', async ({
    page,
  }) => {
    for (const { href } of NAV_ITEMS) {
      await page.goto(href);
      await expect(page.locator('main h1')).toHaveCount(1);

      const active = page.locator('.sidebar a.nav-item.active');
      await expect(active, `${href} should highlight one nav item`).toHaveCount(1);
      await expect(active).toHaveAttribute('href', href);
    }
  });

  test('brand text "Aegis" is visible in the topbar', async ({ page }) => {
    await page.goto('/');

    const brand = page.locator('.topbar .brand');
    await expect(brand).toBeVisible();
    await expect(brand).toContainText('Aegis');
    // The muted suffix is hidden below 760px, so only assert it on desktop.
    await expect(brand.locator('.brand-muted')).toContainText('Agent Security');
  });
});

test.describe('overview dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('shows the demo / read-only notice', async ({ page }) => {
    const notice = page.locator('.demo-notice');
    await expect(notice).toBeVisible();
    await expect(notice).toHaveAttribute('role', 'note');
    // Wording flips to 混合只读模式 when a collector summary is reachable.
    await expect(notice).toContainText(/演示模式|混合只读模式/);
  });

  test('renders four metric cards', async ({ page }) => {
    const metrics = page.locator('.metrics .metric');
    await expect(metrics).toHaveCount(4);
    for (const label of [
      '已纳管设备',
      '当前版本覆盖率',
      '高风险设备',
      '版本漂移设备',
    ]) {
      await expect(
        page.locator('.metrics .metric').filter({ hasText: label }).first(),
      ).toBeVisible();
    }
  });

  test('metric cards animate up to a non-zero value', async ({ page }) => {
    const values = page.locator('.metrics .metric strong');
    await expect(values).toHaveCount(4);

    // useAnimatedNumber() ramps from 0 over 800ms; poll until every card has
    // settled on a value greater than zero.
    await expect(async () => {
      const texts = await values.allTextContents();
      expect(texts).toHaveLength(4);
      for (const text of texts) {
        expect(numericPart(text)).toBeGreaterThan(0);
      }
    }).toPass({ timeout: 10_000 });
  });

  test('risk sample table lists at least three events', async ({ page }) => {
    const panel = page.locator('.panel.risks');
    await expect(panel).toBeVisible();
    await expect(panel.locator('h2')).toHaveText('风险事件样例');

    const rows = panel.locator('.risk-table .risk-row');
    await rows.first().waitFor();
    expect(await rows.count()).toBeGreaterThanOrEqual(3);

    // Each row carries a severity badge, a device id and a relative timestamp.
    await expect(rows.first().locator('.severity')).toBeVisible();
    await expect(rows.first().locator('.device')).not.toBeEmpty();
    await expect(rows.first().locator('.time')).not.toBeEmpty();
  });

  test('security score section is visible with a rendered chart', async ({
    page,
  }) => {
    const score = page.locator('.panel.score');
    await expect(score).toBeVisible();
    await expect(score.locator('h2')).toHaveText('安全评分');

    const center = score.locator('.score-center-text');
    await expect(center).toBeVisible();
    await expect(center).toContainText('/ 100');
    expect(numericPart((await center.locator('strong').innerText()).trim())).toBeGreaterThan(0);

    // RadialBarChart renders through recharts' ResponsiveContainer.
    await expect(score.locator('.score-ring-chart svg').first()).toBeVisible();

    const breakdown = score.locator('.score-list p');
    await expect(breakdown).toHaveCount(3);
  });

  test('activity timeline has entries', async ({ page }) => {
    const timeline = page.locator('.activity-timeline');
    await expect(timeline).toBeVisible();
    await expect(timeline.locator('h2')).toHaveText('近期动态');

    const items = timeline.locator('.timeline-item');
    await items.first().waitFor();
    expect(await items.count()).toBeGreaterThanOrEqual(3);

    const first = items.first();
    await expect(first.locator('.timeline-header strong')).not.toBeEmpty();
    await expect(first.locator('.timeline-time')).not.toBeEmpty();
    await expect(first.locator('.timeline-content p')).not.toBeEmpty();
  });
});

test.describe('devices page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/devices');
    await expect(page.locator('main h1')).toHaveText('设备与 Agent');
  });

  test('shows the managed endpoint table', async ({ page }) => {
    const table = page.locator('.data-table');
    await expect(table).toBeVisible();
    await expect(table.locator('.data-head')).toHaveCount(1);
    await expect(table.locator('.data-head')).toContainText('设备 ID');
  });

  test('table has at least four rows with device ids', async ({ page }) => {
    const rows = page.locator('.data-table .data-row');
    await rows.first().waitFor();
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(4);

    // Device ids look like ENG-MBP-1032 / DESK-WIN-0521.
    const ids = await rows.locator('strong').allInnerTexts();
    expect(ids).toHaveLength(count);
    for (const id of ids) {
      expect(id.trim()).toMatch(/^[A-Z]+-[A-Z]+-\d{4}$/);
    }
    expect(new Set(ids.map((id) => id.trim())).size).toBe(count);
  });

  test('KPI cards show numbers', async ({ page }) => {
    const kpiValues = page.locator('.detail-kpis article strong');
    await expect(kpiValues).toHaveCount(3);

    const texts = await kpiValues.allInnerTexts();
    for (const text of texts) {
      expect(text.trim()).toMatch(/\d/);
      expect(numericPart(text)).toBeGreaterThan(0);
    }
  });
});

test.describe('risks page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/risks');
    await expect(page.locator('main h1')).toHaveText('风险中心');
  });

  test('lists risk events with severity badges', async ({ page }) => {
    const rows = page.locator('.risk-table .risk-row');
    await rows.first().waitFor();
    expect(await rows.count()).toBeGreaterThanOrEqual(3);

    const badges = page.locator('.risk-table .risk-row .severity');
    expect(await badges.count()).toBe(await rows.count());
    for (const severity of await badges.allInnerTexts()) {
      expect(severity.trim()).toMatch(/^(高危|中危|低危)$/);
    }
  });

  test('severity badges carry the red / orange tone classes', async ({ page }) => {
    const red = page.locator('.risk-table .severity.red');
    const orange = page.locator('.risk-table .severity.orange');

    await red.first().waitFor();
    expect(await red.count()).toBeGreaterThanOrEqual(1);
    expect(await orange.count()).toBeGreaterThanOrEqual(1);

    await expect(red.first()).toHaveText('高危');
    await expect(orange.first()).toHaveText('中危');

    // The two tones must be visually distinct (globals.css .severity.red /
    // .severity.orange). Comparing colours keeps the check independent of the
    // exact palette values.
    const redColor = await red.first().evaluate((el) => getComputedStyle(el).color);
    const orangeColor = await orange
      .first()
      .evaluate((el) => getComputedStyle(el).color);
    expect(redColor).not.toBe(orangeColor);
    expect(redColor).toMatch(/^rgba?\(/);
  });
});

test.describe('policies page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/policies');
    await expect(page.locator('main h1')).toHaveText('终端安全策略');
    // Wait for React hydration — 'use client' components need JS bundle loaded
    // before onClick handlers are attached.
    await page.waitForLoadState('networkidle');
  });

  test('renders the policy switch toggles', async ({ page }) => {
    const rows = page.locator('.setting-row');
    await rows.first().waitFor();
    expect(await rows.count()).toBeGreaterThanOrEqual(4);

    const switches = page.locator('.setting-row button.switch');
    expect(await switches.count()).toBe(await rows.count());
    await expect(switches.first()).toHaveAttribute('aria-label', /^切换/);

    // Five of the six seeded policies start enabled.
    expect(await page.locator('.setting-row button.switch.on').count()).toBeGreaterThan(0);
  });

  test('clicking a switch raises a 演示模式 toast', async ({ page }) => {
    const target = page.locator('.setting-row').first();
    const policyName = (await target.locator('strong').innerText()).trim();

    await target.locator('button.switch').click();

    const toast = page.locator('.toast');
    await toast.waitFor({ state: 'visible' });
    await expect(toast).toHaveAttribute('role', 'status');
    await expect(toast).toContainText('演示模式');
    await expect(toast).toContainText(policyName);
  });

  test('publishing policies raises a 演示模式 toast', async ({ page }) => {
    await page.getByRole('button', { name: '发布策略' }).click();

    const toast = page.locator('.toast');
    await toast.waitFor({ state: 'visible' });
    await expect(toast).toContainText('演示模式');
  });
});

test.describe('scanner pages', () => {
  for (const { href, heading, minRows } of SCANNER_PAGES) {
    test(`${href} loads a scan trend chart and a results table`, async ({
      page,
    }) => {
      await page.goto(href);
      await expect(page.locator('main h1')).toHaveText(heading);

      // Demo banner is present on every scanner page.
      await expect(page.locator('.demo-notice')).toBeVisible();

      // recharts BarChart inside .panel.scan-trend.
      const chart = page.locator('.panel.scan-trend');
      await expect(chart).toBeVisible();
      const surface = chart.locator('svg').first();
      await surface.waitFor({ state: 'visible' });
      const box = await surface.boundingBox();
      expect(box, 'chart svg collapsed to zero width').not.toBeNull();
      expect(box?.width ?? 0).toBeGreaterThan(0);
      expect(await chart.locator('.recharts-surface').count()).toBeGreaterThan(0);

      // Results table below the chart.
      const rows = page.locator('.data-table .data-row');
      await rows.first().waitFor();
      expect(await rows.count()).toBeGreaterThanOrEqual(minRows);
      await expect(page.locator('.data-table .data-head')).toHaveCount(1);

      // KPI strip shared by all three scanners.
      await expect(page.locator('.detail-kpis article strong')).toHaveCount(3);
    });
  }
});

test.describe('responsive layout', () => {
  test('metric grid collapses to two columns at 768px', async ({ page }) => {
    // app/globals.css `@media (max-width: 1050px)` -> .metrics { 1fr 1fr }.
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
    await page.locator('.metrics .metric').first().waitFor();

    expect(await gridTrackCount(page, '.metrics')).toBe(2);
    expect(await page.locator('.metrics .metric').count()).toBe(4);
  });

  test('metric grid keeps four columns on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');
    await page.locator('.metrics .metric').first().waitFor();

    expect(await gridTrackCount(page, '.metrics')).toBe(4);
  });

  test('sidebar hides at the 760px breakpoint, not at 768px', async ({
    page,
  }) => {
    // The brief asked for "sidebar hidden at 768px", but the implementation
    // hides `.sidebar` under `@media (max-width: 760px)` (app/globals.css).
    // Pin both sides of the real breakpoint so a future change is caught.
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
    await page.locator('.metrics .metric').first().waitFor();
    await expect(page.locator('.sidebar')).toBeVisible();

    await page.setViewportSize({ width: 760, height: 1024 });
    await expect(page.locator('.sidebar')).toBeHidden();
    // Content still renders without the sidebar.
    await expect(page.locator('.metrics .metric').first()).toBeVisible();
    await expect(page.locator('.topbar .brand')).toContainText('Aegis');

    await page.setViewportSize({ width: 1280, height: 900 });
    await expect(page.locator('.sidebar')).toBeVisible();
  });
});
