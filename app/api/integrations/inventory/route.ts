import { NextResponse } from 'next/server';
import { RESERVED_STUB_BODY } from '@/lib/openapi';

export const dynamic = 'force-dynamic';

/** GET /api/integrations/inventory — 预留桩（绝对要求 #2）：设备/资产清单拉取，点亮前恒 501。 */
export async function GET() {
  return NextResponse.json(RESERVED_STUB_BODY, { status: 501, headers: { 'Cache-Control': 'no-store' } });
}
