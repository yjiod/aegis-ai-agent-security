import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';

export const dynamic = 'force-dynamic';

/** GET /api/auth/me — current session identity + role (for UI gating). */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ authenticated: false }, { status: 401 });
  return NextResponse.json(
    { authenticated: true, subject: session.subject, role: session.role },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
