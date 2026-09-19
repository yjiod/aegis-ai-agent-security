import { expect, test, request as pwRequest, type APIRequestContext } from '@playwright/test';
import { createHmac } from 'node:crypto';

/**
 * 证据导出包 e2e（/api/evidence + /api/evidence/verify）。
 *
 * 覆盖：auditor 生成、viewer 403、未认证 307、sections 过滤、verbose 仅管理员、
 * 生成写 evidence:export 审计、验签往返（正例通过 / 篡改失败）、坏参数 400。
 *
 * 依赖 dev server 环境（见 scripts/run-e2e.sh）：
 *   AEGIS_SESSION_SECRET、AEGIS_ADMIN_USERS=e2eadmin、AEGIS_AUDITOR_USERS=e2eauditor、
 *   AEGIS_POLICY_ED25519_SEED（固定测试种子 → 包必然 ed25519 签名）。
 */

const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;
const SECRET = process.env.AEGIS_SESSION_SECRET ?? 'e2e-secret-0123456789';
const ADMIN = process.env.E2E_ADMIN_USER ?? 'e2eadmin';
const AUDITOR = process.env.E2E_AUDITOR_USER ?? 'e2eauditor';
const VIEWER = 'e2eviewer';

function signedCookie(subject: string, expiry = Date.now() + 3_600_000): string {
  const payload = `${subject}.${expiry}`;
  return `${payload}.${createHmac('sha256', SECRET).update(payload).digest('hex')}`;
}

async function ctxWithCookie(cookieValue: string): Promise<APIRequestContext> {
  return pwRequest.newContext({
    baseURL: BASE_URL,
    storageState: {
      cookies: [{ name: 'aegis_session', value: cookieValue, domain: new URL(BASE_URL).hostname, path: '/', expires: Math.floor(Date.now() / 1000) + 3600, httpOnly: true, secure: false, sameSite: 'Lax' }],
      origins: [],
    },
  });
}

interface Bundle {
  schema: string;
  sections: Record<string, unknown>;
  manifest: Record<string, { count: number; sha256: string }>;
  ed25519_public?: string;
  ed25519_signature?: string;
  integrity?: string;
  report_markdown: string;
}

test.describe('evidence bundle: authorization', () => {
  test('auditor can generate a signed bundle', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const res = await ctx.get('/api/evidence', { maxRedirects: 0 });
      expect(res.status(), 'auditor must generate evidence').toBe(200);
      expect(res.headers()['content-disposition'] ?? '').toContain('attachment');
      const bundle = (await res.json()) as Bundle;
      expect(bundle.schema).toBe('aegis.evidence/v1');
      expect(Object.keys(bundle.manifest).length).toBeGreaterThan(0);
      expect(typeof bundle.report_markdown).toBe('string');
      // dev server 配了 ed25519 seed → 必然签名
      expect(bundle.ed25519_public, 'bundle must be ed25519-signed in e2e').toBeTruthy();
      expect(bundle.ed25519_signature).toBeTruthy();
    } finally {
      await ctx.dispose();
    }
  });

  test('viewer is denied (403)', async () => {
    const ctx = await ctxWithCookie(signedCookie(VIEWER));
    try {
      const res = await ctx.get('/api/evidence', { maxRedirects: 0 });
      expect(res.status(), 'viewer must NOT generate evidence').toBe(403);
    } finally {
      await ctx.dispose();
    }
  });

  test('unauthenticated is gated to login (307)', async () => {
    const anon = await pwRequest.newContext({ baseURL: BASE_URL });
    try {
      const res = await anon.get('/api/evidence', { maxRedirects: 0 });
      expect(res.status()).toBe(307);
      expect(res.headers()['location'] ?? '').toContain('/login');
    } finally {
      await anon.dispose();
    }
  });

  test('verbose redaction requires admin', async () => {
    const auditor = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const denied = await auditor.get('/api/evidence?redaction=verbose', { maxRedirects: 0 });
      expect(denied.status(), 'auditor verbose must be 400').toBe(400);
      const body = (await denied.json()) as { details?: string[] };
      expect((body.details ?? []).join(' ')).toContain('admin');
    } finally {
      await auditor.dispose();
    }
    const admin = await ctxWithCookie(signedCookie(ADMIN));
    try {
      const ok = await admin.get('/api/evidence?redaction=verbose&sections=inventory', { maxRedirects: 0 });
      expect(ok.status(), 'admin verbose must succeed').toBe(200);
    } finally {
      await admin.dispose();
    }
  });
});

test.describe('evidence bundle: params + audit', () => {
  test('sections filter is honored', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const res = await ctx.get('/api/evidence?sections=inventory,policy', { maxRedirects: 0 });
      expect(res.status()).toBe(200);
      const bundle = (await res.json()) as Bundle;
      expect(Object.keys(bundle.sections).sort()).toEqual(['inventory', 'policy']);
      expect(Object.keys(bundle.manifest).sort()).toEqual(['inventory', 'policy']);
    } finally {
      await ctx.dispose();
    }
  });

  test('bad params are rejected (400)', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const badSection = await ctx.get('/api/evidence?sections=nope', { maxRedirects: 0 });
      expect(badSection.status()).toBe(400);
      const badWindow = await ctx.get('/api/evidence?since=2000&until=1000', { maxRedirects: 0 });
      expect(badWindow.status()).toBe(400);
      const badDevice = await ctx.get('/api/evidence?device_id=!!bad!!', { maxRedirects: 0 });
      expect(badDevice.status()).toBe(400);
    } finally {
      await ctx.dispose();
    }
  });

  test('generating writes an evidence:export audit entry', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const gen = await ctx.get('/api/evidence?sections=audit', { maxRedirects: 0 });
      expect(gen.status()).toBe(200);
      const audit = await ctx.get('/api/audit?action=evidence:export&limit=50', { maxRedirects: 0 });
      expect(audit.status()).toBe(200);
      const body = (await audit.json()) as { entries?: Array<{ action: string; detail?: string }> };
      const hit = (body.entries ?? []).find((e) => e.action === 'evidence:export');
      expect(hit, 'evidence:export must be audited').toBeTruthy();
      expect(hit?.detail ?? '').toContain('sha256=');
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('evidence bundle: verify round-trip', () => {
  test('valid bundle verifies; tampered bundle fails', async () => {
    const ctx = await ctxWithCookie(signedCookie(AUDITOR));
    try {
      const gen = await ctx.get('/api/evidence', { maxRedirects: 0 });
      expect(gen.status()).toBe(200);
      const bundle = (await gen.json()) as Bundle;

      const good = await ctx.post('/api/evidence/verify', { data: bundle });
      expect(good.status()).toBe(200);
      const gv = (await good.json()) as { ok: boolean; schema_ok: boolean; manifest_ok: boolean; ed25519_ok: boolean | null };
      expect(gv.schema_ok).toBe(true);
      expect(gv.manifest_ok).toBe(true);
      expect(gv.ed25519_ok).toBe(true);
      expect(gv.ok).toBe(true);

      // 篡改一个 section（不改 manifest）→ manifest 不符 + 签名失败
      const tampered = JSON.parse(JSON.stringify(bundle)) as Bundle;
      const firstSection = Object.keys(tampered.sections)[0];
      (tampered.sections[firstSection] as unknown) = ['tampered'];
      const bad = await ctx.post('/api/evidence/verify', { data: tampered });
      expect(bad.status()).toBe(200);
      const bv = (await bad.json()) as { ok: boolean; manifest_ok: boolean; ed25519_ok: boolean | null };
      expect(bv.ok).toBe(false);
      expect(bv.manifest_ok).toBe(false);
    } finally {
      await ctx.dispose();
    }
  });

  test('verify denies viewer (403)', async () => {
    const ctx = await ctxWithCookie(signedCookie(VIEWER));
    try {
      const res = await ctx.post('/api/evidence/verify', { data: { schema: 'aegis.evidence/v1' } });
      expect(res.status()).toBe(403);
    } finally {
      await ctx.dispose();
    }
  });
});
