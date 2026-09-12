import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { ensurePgHydrated } from '@/lib/store';
import { startUpstreamSyncLoop } from '@/lib/baselines';
import { startIntegrationAlertSync } from '@/lib/integrations';

/**
 * Session guard: all console pages require a valid aegis_session cookie.
 * Exempt: /login, /api/auth/*, static assets (_next, favicon), /aegis/* (Collector API).
 *
 * Also triggers one-time PostgreSQL hydration. workerd rejects async I/O at
 * module/global scope, so the stores cannot hydrate at import time; middleware
 * runs per-request in handler scope (and its matcher covers /api routes), so it
 * is the correct place to lazily load durable state from PG before any route
 * handler reads the stores. Cached after the first request; a PG failure is
 * swallowed so it never blocks traffic (console degrades to file/in-memory).
 */
export async function middleware(request: NextRequest) {
  await ensurePgHydrated().catch(() => {});
  startUpstreamSyncLoop();
  startIntegrationAlertSync();
  const { pathname } = request.nextUrl;

  // Exempt paths
  if (
    pathname === '/login' ||
    pathname.startsWith('/api/auth') ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/aegis') ||
    pathname === '/favicon.svg' ||
    pathname.startsWith('/downloads')
  ) {
    return NextResponse.next();
  }

  const session = request.cookies.get('aegis_session')?.value;

  if (!session) {
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('from', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Validate session format: username.expiry.signature
  const parts = session.split('.');
  if (parts.length !== 3) {
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  const [, expiryStr] = parts;
  const expiry = Number(expiryStr);
  if (!Number.isFinite(expiry) || expiry < Date.now()) {
    const loginUrl = new URL('/login', request.url);
    const response = NextResponse.redirect(loginUrl);
    response.cookies.delete('aegis_session');
    return response;
  }

  // Signature verification happens server-side in each API route / page as needed.
  // Here we only check presence + expiry for the redirect gate.
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
