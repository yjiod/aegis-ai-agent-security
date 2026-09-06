import { expect, test } from '@playwright/test';

/**
 * Contract coverage for the read-only collector proxy at /api/summary.
 *
 * app/api/summary/route.ts has two outcomes:
 *   1. collector configured + reachable + contract valid -> 200 { connected: true, summary }
 *   2. anything else -> 5xx { connected: false, error }
 * Both paths set `Cache-Control: no-store`, and the console shell treats a
 * non-`connected` response as "demo mode", so the test accepts either shape.
 */

const SUMMARY_PATH = '/api/summary';

/** HTTP statuses the route is allowed to return. */
const ACCEPTED_STATUSES = [200, 502, 503];

const LEVELS = ['critical', 'high', 'normal'] as const;
const POSTURES = [
  'current',
  'agent_mismatch',
  'policy_mismatch',
  'both_mismatch',
  'unknown',
] as const;

type Summary = {
  total_devices: number;
  active_devices: number;
  stale_devices: number;
  required_agent_version: string;
  required_policy_version: string;
  latest_severity: Record<string, number>;
  version_posture: Record<string, number>;
  credential_posture?: Record<string, number>;
};

test.describe('GET /api/summary', () => {
  test('responds with a JSON document', async ({ request }) => {
    const response = await request.get(SUMMARY_PATH);

    expect(
      ACCEPTED_STATUSES,
      `unexpected status ${response.status()}`,
    ).toContain(response.status());
    expect(response.headers()['content-type']).toContain('application/json');

    const body = (await response.json()) as {
      connected?: unknown;
      error?: unknown;
      summary?: unknown;
    };
    expect(typeof body).toBe('object');
    expect(body).not.toBeNull();
    expect(typeof body.connected, 'connected flag must be a boolean').toBe(
      'boolean',
    );

    if (body.connected === true) {
      // 200 path: a sanitized summary must be attached.
      expect(response.status()).toBe(200);
      expect(body.summary, 'connected:true requires a summary').toBeTruthy();
    } else {
      // Demo path: the console falls back to sample data, and the route always
      // explains why the collector is unusable.
      expect(body.summary).toBeUndefined();
      expect(typeof body.error).toBe('string');
      expect((body.error as string).length).toBeGreaterThan(0);
    }
  });

  test('response carries Cache-Control: no-store', async ({ request }) => {
    const response = await request.get(SUMMARY_PATH);

    expect(ACCEPTED_STATUSES).toContain(response.status());
    expect(response.headers()['cache-control']).toBe('no-store');
  });

  test('connected summaries satisfy the internal consistency contract', async ({
    request,
  }) => {
    const response = await request.get(SUMMARY_PATH);
    const body = (await response.json()) as {
      connected: boolean;
      summary?: Summary;
    };

    test.skip(
      body.connected !== true || !body.summary,
      'collector not connected in this environment; demo mode is expected',
    );

    const summary = body.summary as Summary;
    expect(typeof summary.total_devices).toBe('number');
    expect(summary.active_devices + summary.stale_devices).toBe(
      summary.total_devices,
    );
    expect(summary.required_agent_version).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
    expect(summary.required_policy_version).toMatch(/^[A-Za-z0-9._-]{1,64}$/);

    const severityTotal = LEVELS.reduce(
      (sum, key) => sum + Number(summary.latest_severity?.[key] ?? -1),
      0,
    );
    expect(severityTotal).toBe(summary.total_devices);

    const postureTotal = POSTURES.reduce(
      (sum, key) => sum + Number(summary.version_posture?.[key] ?? -1),
      0,
    );
    expect(postureTotal).toBe(summary.total_devices);
  });
});
