import { NextResponse } from 'next/server';
import { RESERVED_STUB_BODY } from '@/lib/openapi';

export const dynamic = 'force-dynamic';

/** GET /api/integrations/health — 预留桩（公开）：模块存活探针，点亮前恒 501。 */
export async function GET() {
  return NextResponse.json(RESERVED_STUB_BODY, { status: 501, headers: { 'Cache-Control': 'no-store' } });
}
