import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { pgStatus, ensurePgHydrated } from '@/lib/store';

export const dynamic = 'force-dynamic';

/**
 * GET /api/admin/pg-status — operator-visible PostgreSQL health (admin-only).
 *
 * Surfaces whether PG is configured, reachable, and whether hydration
 * succeeded, plus live row counts. This exists so a silent PG outage can never
 * masquerade as durability: if `configured` is true but `reachable` is false,
 * the console has degraded to the JSON file mirror and an operator must act.
 */
export async function GET(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  // Ensure hydration has settled (request scope) before reporting counts.
  await ensurePgHydrated().catch(() => {});
  const status = await pgStatus();
  return NextResponse.json(status, {
    headers: { 'Cache-Control': 'no-store' },
  });
}
