import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { ensurePgHydrated } from '@/lib/store';
import { startUpstreamSyncLoop } from '@/lib/baselines';
import { startIntegrationAlertSync } from '@/lib/integrations';
import { startAutoRemediationLoop } from '@/lib/auto-remediation';
import {
  refreshSessionRevocations,
  refreshOperators,
  refreshDevelopers,
  sessionRevokedBefore,
  SESSION_TTL_MS,
} from '@/lib/auth';

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
  // 预热会话吊销缓存（30s TTL；PG 不可用 fail-open，不阻塞流量）。
  await refreshSessionRevocations().catch(() => {});
  // 预热 operator 白名单缓存（60s TTL；写操作 invalidate）。
  await refreshOperators().catch(() => {});
  await refreshDevelopers().catch(() => {});
  startUpstreamSyncLoop();
  startIntegrationAlertSync();
  startAutoRemediationLoop();
  const { pathname } = request.nextUrl;

  // Dev-only component catalog (fabricated data) must never be reachable in prod.
  if (pathname.startsWith('/catalog') && process.env.NODE_ENV === 'production') {
    return NextResponse.redirect(new URL('/', request.url));
  }

  // Exempt paths
  if (
    pathname === '/login' ||
    pathname.startsWith('/api/auth') ||
    pathname === '/api/policy/artifact' ||
    pathname === '/api/policy/verify-key' || // 公开验签公钥（公钥非秘密，批3）
    pathname === '/api/enroll' ||
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

  // 4A 会话吊销：签发时间(expiry-7d)早于该 subject 的 invalid_before 即已吊销
  // （改密/移除白名单/管理员显式吊销）。页面请求回登录并清 Cookie；API 的权威
  // 拒绝由各路由 getSession/parseSession 完成（401）。
  const subject = parts.slice(0, parts.length - 2).join('.');
  const issued = expiry - SESSION_TTL_MS;
  if (subject && issued < sessionRevokedBefore(subject)) {
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
