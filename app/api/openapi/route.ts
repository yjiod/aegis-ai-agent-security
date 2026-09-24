import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { openApiDoc } from '@/lib/openapi';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * GET /api/openapi — 全系统 API 契约（OpenAPI 3.1，绝对要求 #2）。
 * 需登录会话（契约描述内部 API 面，不对匿名暴露）。预留端点带 x-reserved=true。
 */
export async function GET(request: Request) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  return NextResponse.json(openApiDoc(), { headers: { ...NO_STORE, 'Content-Type': 'application/json; charset=utf-8' } });
}
