import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright E2E configuration for the Aegis Agent security console.
 *
 * Notes:
 * - Only chromium is enabled on purpose: the suite is a smoke/regression net
 *   for critical console paths and needs to stay fast in CI.
 * - The suite runs against the vinext dev server (`npm run dev`). Browser
 *   binaries are intentionally NOT vendored here; CI is expected to run
 *   `npx playwright install --with-deps chromium` before `npm run test:e2e`.
 * - Workers are capped at 2 because the dev server compiles each App Router
 *   segment on first request; too much concurrency makes cold-start navigations
 *   slow enough to look like flakes.
 */

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',

  /* Fail fast on a single test, but keep the suite moving. */
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },

  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: 2,

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],

  use: {
    baseURL: BASE_URL,
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: {
    command: 'npm run dev',
    url: BASE_URL,
    reuseExistingServer: true,
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
