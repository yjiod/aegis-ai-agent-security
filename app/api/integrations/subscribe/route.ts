import { NextResponse } from 'next/server';
import { RESERVED_STUB_BODY } from '@/lib/openapi';

export const dynamic = 'force-dynamic';

/** 预留桩（绝对要求 #2/4A：保留接口、不做强制对接）：点亮前恒 501 + 稳定契约体。 */
export async function POST() {
  return NextResponse.json(RESERVED_STUB_BODY, { status: 501, headers: { 'Cache-Control': 'no-store' } });
}
