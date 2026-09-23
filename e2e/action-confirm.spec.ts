import { expect, test, type Page } from '@playwright/test';

/**
 * 统一不可逆动作确认弹窗（ActionConfirmDialog）回归 e2e。
 *
 * 这是首个「认证态 UI」用例：通过 API 登录拿到 aegis_session cookie 注入浏览器
 * 上下文（避免 UI 登录水合抖动），再验证点击高危动作柄后弹出统一确认弹窗，
 * 且弹窗如实展示「影响范围 / 回滚 / 操作人」，取消后不发生任何变更。
 *
 * 注意：dev server 存在长连接（HMR / 实时态），networkidle 永不收敛，故一律
 * 以「目标元素可见」作为水合完成信号（团队页行由客户端 fetch 后渲染，可见即已挂载）。
 *
 * 凭据与 dev server 一致（run-e2e.sh 注入 AEGIS_CONSOLE_USER/PASSWORD）。
 */

const USER = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const PASS = process.env.E2E_ADMIN_PASSWORD ?? 'E2e-Pass-123';
const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

/** API 登录并把 aegis_session cookie 注入浏览器上下文，得到已认证页面。 */
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

/** 团队页中该工号行的「吊销会话」动作柄（高危、非破坏性，取消即无副作用）。 */
function revokeHandle(page: Page) {
  return page
    .locator('.data-row', { hasText: USER })
    .locator('button.handle', { hasText: '吊销会话' })
    .first();
}

test.describe('unified action-confirm dialog', () => {
  test('irreversible team action opens confirm dialog with impact + rollback, cancel mutates nothing', async ({
    page,
  }) => {
    await authedPage(page);
    await page.goto('/team');

    const revoke = revokeHandle(page);
    await expect(revoke).toBeVisible({ timeout: 20_000 });
    await revoke.click();

    const dialog = page.locator('[data-slot="alert-dialog-content"]');
    await expect(dialog).toBeVisible();
    // 弹窗必须如实展示影响范围 / 回滚 / 操作人（handoff P0：动作前可见影响与回滚）。
    await expect(dialog).toContainText('影响范围');
    await expect(dialog).toContainText('回滚');
    await expect(dialog).toContainText('操作人');
    await expect(dialog).toContainText('吊销');

    // 取消：弹窗关闭，且不触发任何变更（仍能看到该工号行的动作柄）。
    await dialog.locator('button', { hasText: '取消' }).click();
    await expect(dialog).toBeHidden();
    await expect(revokeHandle(page)).toBeVisible();
  });

  test('native window.confirm is fully retired from action pages', async ({ page }) => {
    // 守护：确保不可逆动作不再依赖浏览器原生 confirm（已被统一弹窗取代）。
    await authedPage(page);
    let nativeConfirmFired = false;
    page.on('dialog', (d) => {
      nativeConfirmFired = true;
      void d.dismiss();
    });
    await page.goto('/team');

    const revoke = revokeHandle(page);
    await expect(revoke).toBeVisible({ timeout: 20_000 });
    await revoke.click();

    await expect(page.locator('[data-slot="alert-dialog-content"]')).toBeVisible();
    expect(nativeConfirmFired, 'native window.confirm must not fire').toBe(false);
  });
});
