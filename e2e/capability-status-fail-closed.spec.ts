import { expect, test } from '@playwright/test';
import { createHmac } from 'node:crypto';

/**
 * 审计 #32（P0，虚假状态）回归守护：总览页能力卡**绝不 fail-open**。
 *
 * 背景：四张能力卡曾把 `status:'已启用', tone:'green'` 写死在源码里，于是无论终端
 * 实际是否在扫描，总览页永远显示绿色「已启用」+ 对勾 —— 管理决策面谎报安全控制状态。
 * 修复后状态改由 `GET /api/settings/modules` 的**有效值**派生（app/page.tsx 的
 * moduleCardStatus），并遵循 fail-closed：接口加载中/失败一律中性灰「状态未知」，
 * 绝不回落成绿色。
 *
 * 本文件守的就是这条 fail-closed 边界。**它的价值在于防回归**：将来若有人把失败路径
 * "优化"成回落默认值（fail-open），这里立刻变红。
 *
 * 断言按 app/page.tsx 的真实实现写，不猜 DOM：
 *  - 卡 1「终端 Agent 发现」的 `key === null`，moduleCardStatus 在读 modsError **之前**
 *    就返回「随 Agent 常驻」——它不依赖接口，故接口失败时也**不会**显示「状态未知」。
 *    断言若写成"四张卡全部状态未知"就是错的。
 *  - 只有三张有开关的卡（Skill 扫描器 / MCP 扫描器 / 代码质量扫描）走 modsError 分支。
 *  - 芯片是 `<span class="status {tone}">`，对勾是其中的 `<Check size={13}/>` svg，
 *    仅在 `st.check === true`（唯一用绿的分支）时渲染。
 */

const SESSION_SECRET = process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789';
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';

/** PM §7.1 定稿文案（app/page.tsx MODULES_UNAVAILABLE_LABEL，逐字）。 */
const UNAVAILABLE_BANNER = '状态未知 · 读取模块开关失败';

/** 三张由模块开关派生状态的卡（卡 1 无开关，不在此列）。 */
const KEYED_CARDS = ['Skill 扫描器', 'MCP 扫描器', '代码质量扫描'] as const;
/** 无开关、状态恒为「随 Agent 常驻」的卡。 */
const AGENT_CARD = '终端 Agent 发现';

/** 与 e2e/console.spec.ts 同一套会话注入：控制台页在会话中间件之后。 */
test.beforeEach(async ({ context }) => {
  const expiry = Date.now() + 3_600_000;
  const payload = `${ADMIN_USER}.${expiry}`;
  const sig = createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  await context.addCookies([
    {
      name: 'aegis_session',
      value: `${payload}.${sig}`,
      domain: 'localhost',
      path: '/',
      expires: Math.floor(Date.now() / 1000) + 3600,
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
    },
  ]);
});

/** 用 pathname 谓词而非 glob 拦截，免遭 `*` 不跨 `/`、查询串等细节影响。 */
const isModulesApi = (url: URL): boolean => url.pathname === '/api/settings/modules';

test.describe('capability cards never fail open (#32)', () => {
  test('modules API 500 -> keyed cards show 状态未知, never green 已启用, never a checkmark', async ({
    page,
  }) => {
    let intercepted = 0;
    await page.route(isModulesApi, async (route) => {
      intercepted += 1;
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'injected_by_e2e' }),
      });
    });

    await page.goto('/');
    await expect(page.locator('main h1')).toHaveText('AI Agent 安全总览');

    // 反 vacuity 前置：拦截必须真的命中过。否则本用例会因"接口其实是通的"而假绿——
    // 那正是这类测试最隐蔽的失效方式（绿着，但什么都没验）。
    await expect(page.getByText(UNAVAILABLE_BANNER)).toBeVisible();
    expect(
      intercepted,
      'GET /api/settings/modules must have been intercepted, otherwise this test proves nothing',
    ).toBeGreaterThan(0);

    const grid = page.locator('.module-grid');
    await expect(grid).toBeVisible();
    const cards = grid.locator('article.module');
    await expect(cards).toHaveCount(4);
    // 必须等加载态退出再断言：`读取中…` 也是 muted 且无对勾，若不等待就会在
    // "还没读到数据"的状态上通过全部 fail-closed 断言——同样是假绿。
    await expect(grid.getByText('读取中…')).toHaveCount(0);

    // 三张有开关的卡：全部中性灰「状态未知」
    for (const title of KEYED_CARDS) {
      const chip = grid
        .locator('article.module', { hasText: title })
        .locator('.status');
      await expect(chip, `${title} 必须显示「状态未知」`).toHaveText('状态未知');
      await expect(chip, `${title} 的芯片必须是中性灰 muted（禁绿禁红）`).toHaveClass(
        /(?:^|\s)status\s+muted(?:\s|$)/,
      );
    }

    // 无开关的卡 1：不受接口影响，仍陈述事实，且同样不得为绿
    const agentChip = grid
      .locator('article.module', { hasText: AGENT_CARD })
      .locator('.status');
    await expect(agentChip).toHaveText('随 Agent 常驻');
    await expect(agentChip).toHaveClass(/(?:^|\s)status\s+muted(?:\s|$)/);

    // ── 核心红线：绝不 fail-open ────────────────────────────────────────
    // 绿色「已启用」与对勾是"该能力确实在跑"的唯一合法表达；接口失败时出现任何一个
    // 都等于谎报安全控制状态。
    await expect(grid.locator('.status.green')).toHaveCount(0);
    await expect(grid.locator('.module-icon.green')).toHaveCount(0);
    await expect(grid.getByText('已启用', { exact: true })).toHaveCount(0);
    // 对勾只在 st.check===true 时渲染；灰字 + 对勾自相矛盾，必须一个都没有。
    await expect(grid.locator('.status svg')).toHaveCount(0);
    // 也不许用红色/琥珀冒充告警（设计师规则：未知态一律中性灰）
    await expect(grid.locator('.status.warn')).toHaveCount(0);
    await expect(grid.locator('.status.fail')).toHaveCount(0);

    // 重试入口必须存在（PM §7.1：中性灰 + 重试入口）
    await expect(page.getByRole('button', { name: '重试' })).toBeVisible();
  });

  test('control: with the modules API healthy, cards resolve to a real state (proves the test above is not vacuous)', async ({
    page,
  }) => {
    // 不拦截。此用例是上一条的**对照组**：若页面因别的原因恒显「状态未知」，
    // 上一条会假绿，而这一条会红。两条合起来才真正锁定 fail-closed 语义。
    await page.goto('/');
    await expect(page.locator('main h1')).toHaveText('AI Agent 安全总览');

    const grid = page.locator('.module-grid');
    await expect(grid).toBeVisible();
    await expect(grid.locator('article.module')).toHaveCount(4);

    // 等加载态退出。实测教训：不等的话三张有开关的卡还停在「读取中…」，
    // 于是"没有状态未知"会通过、而"有绿色已启用"会失败——两条都得出错误结论。
    await expect(grid.getByText('读取中…')).toHaveCount(0, { timeout: 15000 });

    // 接口正常时：既不该有失败横幅，也不该有任何「状态未知」芯片。
    await expect(page.getByText(UNAVAILABLE_BANNER)).toHaveCount(0);
    await expect(grid.getByText('状态未知', { exact: true })).toHaveCount(0);

    // 三张有开关的卡必须各自落到一个**确定**状态（已启用 / 已停用…），
    // 不锁定具体是哪一个——那取决于当前开关值与其它用例可能留下的持久化状态，
    // 锁死会造成无谓的脆弱。这里只要求"不是未知"，即状态确实被解析出来了。
    for (const title of KEYED_CARDS) {
      const text = (
        await grid.locator('article.module', { hasText: title }).locator('.status').innerText()
      ).trim();
      expect(text, `${title} 应解析出确定状态`).not.toBe('状态未知');
      expect(text.length, `${title} 的状态文案不应为空`).toBeGreaterThan(0);
    }

    // 出厂默认下 skill_scan/mcp_scan 为 true ⇒ 应当真的出现绿色「已启用」+ 对勾。
    // 若某环境把开关全关了，此断言会失败并提示"绿色分支从未被覆盖"——那是有价值的信号，
    // 不是脆弱：说明本套件再也没验证过"确实读到开着"这条唯一可用绿的路径。
    const greenCount = await grid.locator('.status.green').count();
    const checkCount = await grid.locator('.status svg').count();
    expect(
      greenCount,
      'expected at least one module genuinely reported as enabled (green); ' +
        'if all modules are off in this environment, the green path is never covered',
    ).toBeGreaterThan(0);
    expect(checkCount, '对勾数量应与绿色芯片数量一致').toBe(greenCount);
  });
});
