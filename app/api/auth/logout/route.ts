import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { logAudit } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/auth/logout — 服务端登出（4A · Accounting）。
 *
 * 此前登出仅由客户端清 Cookie（console-shell），服务端对此毫无记录，且无法
 * 区分"用户主动登出"与"会话自然过期"。本路由在服务端记录 auth:logout 审计
 * （actor 为会话 subject），并下发 Set-Cookie 使 aegis_session 立即失效。
 *
 * 注意：当前会话为无状态 HMAC Cookie，本路由清除的是"本浏览器"的 Cookie；
 * 跨设备的会话吊销（token 版本/黑名单）属后续 4A 增量（见 PM 队列），此处不
 * 假装已实现。未认证调用也安全（幂等清 Cookie + 返回 ok）。
 */
export async function POST(request: Request) {
  const session = getSession(request);
  if (session) {
    logAudit({
      actor: session.subject,
      action: 'auth:logout',
      resource_type: 'system',
      detail: 'server-side logout',
    });
  }
  const response = NextResponse.json({ ok: true }, { headers: HEADERS });
  response.cookies.set('aegis_session', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
  return response;
}
