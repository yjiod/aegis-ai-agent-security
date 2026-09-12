import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/** TEMP debug: run the collector->ticket sync and surface any error. */
export async function GET() {
  const url = process.env.AEGIS_COLLECTOR_URL;
  const token = process.env.AEGIS_COLLECTOR_TOKEN;
  const out: Record<string, unknown> = { has_url: Boolean(url), has_token: Boolean(token) };
  if (!url || !token) return NextResponse.json(out);
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/devices?limit=500`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      cache: 'no-store',
    });
    out.fetch_status = res.status;
    const data = (await res.json()) as { devices?: Array<Record<string, unknown>> };
    out.device_count = (data.devices ?? []).length;
    out.first = (data.devices ?? [])[0];
  } catch (e) {
    out.error = String(e);
  }
  return NextResponse.json(out);
}
