import { expect, test, request as pwRequest, type APIRequestContext } from '@playwright/test';
import { createHmac, createHash } from 'node:crypto';

/**
 * 自更新灰度（canary）e2e：/api/settings/rollout 权限/校验/持久化，以及
 * /api/devices 暴露的 rollout_bucket / in_canary 与参考算法（=终端 python in_rollout）
 * 的跨语言对拍。
 *
 * 对拍向量由 python hashlib.sha256(did).hexdigest() 的 int%100 预先算出并硬编码，
 * 锁定 TS 实现与终端 aegis_self_update.in_rollout 逐位一致（否则 canary 预览失真）。
 */

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;
const SECRET = process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789';
const ADMIN = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const AUDITOR = process.env.E2E_AUDITOR_USER ?? 'e2eauditor';
const VIEWER = 'e2eviewer';

// python: int(sha256(did).hexdigest(),16)%100
const PARITY: Record<string, number> = {
  'dev-canary-1': 4,
  'aegis-test-0002': 18,
  'ffffffffffff': 96,
};

function signedCookie(subject: string, expiry = Date.now() + 3_600_000): string {
  const payload = `${subject}.${expiry}`;
  return `${payload}.${createHmac('sha256', SECRET).update(payload).digest('hex')}`;
}
async function ctxWithCookie(v: string): Promise<APIRequestContext> {
  return pwRequest.newContext({
    baseURL: BASE_URL,
    storageState: { cookies: [{ name: 'aegis_session', value: v, domain: new URL(BASE_URL).hostname, path: '/', expires: Math.floor(Date.now() / 1000) + 3600, httpOnly: true, secure: false, sameSite: 'Lax' }], origins: [] },
  });
}
function refBucket(deviceId: string): number {
  const hex = createHash('sha256').update(deviceId).digest('hex');
  let acc = 0;
  for (const c of hex) acc = (acc * 16 + Number.parseInt(c, 16)) % 100;
  return acc;
}

test.describe('rollout settings: authorization + validation', () => {
  test('admin reads current rollout config', async () => {
    const ctx = await ctxWithCookie(signedCookie(ADMIN));
    try {
      const res = await ctx.get('/api/settings/rollout', { maxRedirects: 0 });
      expect(res.status()).toBe(200);
      const body = (await res.json()) as { rollout?: { enabled: boolean; channel: string; rollout_percent: number }; channels?: string[] };
      expect(body.rollout).toBeTruthy();
      expect(typeof body.rollout?.rollout_percent).toBe('number');
      expect(Array.isArray(body.channels) && body.channels?.includes('pilot')).toBe(true);
    } finally { await ctx.dispose(); }
  });

  test('admin can update and it persists', async () => {
    const ctx = await ctxWithCookie(signedCookie(ADMIN));
    try {
      const put = await ctx.put('/api/settings/rollout', { data: { enabled: true, channel: 'beta', rollout_percent: 25 } });
      expect(put.status()).toBe(200);
      const saved = (await put.json()) as { rollout?: { channel: string; rollout_percent: number } };
      expect(saved.rollout?.channel).toBe('beta');
      expect(saved.rollout?.rollout_percent).toBe(25);
      const get = await ctx.get('/api/settings/rollout', { maxRedirects: 0 });
      const body = (await get.json()) as { rollout?: { channel: string; rollout_percent: number } };
      expect(body.rollout?.channel).toBe('beta');
      expect(body.rollout?.rollout_percent).toBe(25);
      // 还原默认，避免影响其它用例
      await ctx.put('/api/settings/rollout', { data: { enabled: true, channel: 'pilot', rollout_percent: 50 } });
    } finally { await ctx.dispose(); }
  });

  test('invalid channel and out-of-range percent are rejected (400)', async () => {
    const ctx = await ctxWithCookie(signedCookie(ADMIN));
    try {
      const badChannel = await ctx.put('/api/settings/rollout', { data: { channel: 'not-a-channel' } });
      expect(badChannel.status()).toBe(400);
      const bc = (await badChannel.json()) as { details?: string[] };
      expect((bc.details ?? []).join(' ')).toContain('channel');

      const badPct = await ctx.put('/api/settings/rollout', { data: { rollout_percent: 150 } });
      expect(badPct.status()).toBe(400);
      const bp = (await badPct.json()) as { details?: string[] };
      expect((bp.details ?? []).join(' ')).toContain('rollout_percent');
    } finally { await ctx.dispose(); }
  });

  test('auditor and viewer cannot mutate (403); unauthenticated gated (307)', async () => {
    const auditor = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const put = await auditor.put('/api/settings/rollout', { data: { rollout_percent: 10 } });
      expect(put.status(), 'auditor must not mutate rollout').toBe(403);
      const get = await auditor.get('/api/settings/rollout', { maxRedirects: 0 });
      expect(get.status(), 'auditor may read rollout').toBe(200);
    } finally { await auditor.dispose(); }

    const viewer = await ctxWithCookie(signedCookie(VIEWER));
    try {
      const put = await viewer.put('/api/settings/rollout', { data: { rollout_percent: 10 } });
      expect(put.status()).toBe(403);
    } finally { await viewer.dispose(); }

    const anon = await pwRequest.newContext({ baseURL: BASE_URL });
    try {
      const res = await anon.get('/api/settings/rollout', { maxRedirects: 0 });
      expect(res.status()).toBe(307);
      expect(res.headers()['location'] ?? '').toContain('/login');
    } finally { await anon.dispose(); }
  });
});

test.describe('rollout cohort: cross-language bucket parity', () => {
  test('server rollout_bucket matches python in_rollout for known device_ids', async () => {
    const ctx = await ctxWithCookie(signedCookie(ADMIN));
    const created: string[] = [];
    try {
      // 先确认参考实现与硬编码的 python 向量一致（锁定算法本身）
      for (const [did, bucket] of Object.entries(PARITY)) expect(refBucket(did), `ref bucket ${did}`).toBe(bucket);

      // 创建一台已知 device_id 的注册设备，验证服务端算出的桶号与 python 向量一致
      const deviceId = 'aegis-test-0002'; // python bucket = 18
      const post = await ctx.post('/api/devices', { data: { device_id: deviceId, hostname: 'canary-parity', owner: 'e2e', agent_type: 'other' } });
      expect([200, 201, 409]).toContain(post.status()); // 409=已存在也可接受
      if (post.status() !== 409) created.push(deviceId);

      const list = await ctx.get('/api/devices', { maxRedirects: 0 });
      expect(list.status()).toBe(200);
      const body = (await list.json()) as { devices?: Array<{ device_id: string; rollout_bucket?: number; in_canary?: boolean }> };
      const devices = body.devices ?? [];
      const target = devices.find((d) => d.device_id === deviceId);
      expect(target, 'created device must appear with cohort fields').toBeTruthy();
      expect(target?.rollout_bucket, 'server bucket must equal python in_rollout bucket').toBe(PARITY[deviceId]);

      // 自洽：所有设备的 in_canary 必须等于 bucket 与当前放量比例的关系
      const cfgRes = await ctx.get('/api/settings/rollout', { maxRedirects: 0 });
      const cfg = ((await cfgRes.json()) as { rollout?: { rollout_percent: number } }).rollout;
      const pct = cfg?.rollout_percent ?? 50;
      for (const d of devices) {
        if (typeof d.rollout_bucket !== 'number') continue;
        const expected = pct >= 100 ? true : pct <= 0 ? false : d.rollout_bucket < pct;
        expect(d.in_canary, `in_canary for ${d.device_id} @${pct}%`).toBe(expected);
        expect(d.rollout_bucket, `bucket recompute for ${d.device_id}`).toBe(refBucket(d.device_id));
      }
    } finally {
      for (const id of created) await ctx.delete(`/api/devices?device_id=${encodeURIComponent(id)}`).catch(() => {});
      await ctx.dispose();
    }
  });
});
