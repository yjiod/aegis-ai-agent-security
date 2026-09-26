import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import { runAutoRemediationSweep } from '@/lib/auto-remediation';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/**
 * POST /api/remediation/auto-sweep — 立即执行一轮全自动纠偏（绝对要求 #3）。
 * admin-only（后台循环也走同一实现）；结果含：自动封禁清单、人工冲突、
 * 通知计数与发布版本。自动路径永不使用爆炸半径 override。
 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const result = await runAutoRemediationSweep('console-manual');
  return NextResponse.json(result, { status: result.reason === 'labels_unavailable' ? 503 : 200, headers: NO_STORE });
}
