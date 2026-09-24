import { NextResponse } from 'next/server';
import { getSession } from '@/lib/auth';
import { loadPipelineTelemetry, parseStages } from '@/lib/pipeline-telemetry';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

export interface PipelineTelemetryEvent {
  ts: number;
  pipeline: string;
  source: string;
  stages: Array<{ name: string; ok: boolean; detail?: string }>;
  ok: boolean;
  latency_ms: number;
  actor: string;
  detail: string;
}

/**
 * GET /api/pipeline/telemetry — 规则更新管道真实遥测（策略发布 / 基线同步 / 企业 MD 发布）。
 * 无 PG / 无活动时返回 connected:false + 空列表，UI 诚实显示空态，绝不伪造流水。
 */
export async function GET(request: Request): Promise<NextResponse> {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401, headers: NO_STORE });
  const rows = await loadPipelineTelemetry(20).catch(() => null);
  if (!rows) return NextResponse.json({ connected: false, events: [] as PipelineTelemetryEvent[] }, { headers: NO_STORE });
  const events: PipelineTelemetryEvent[] = rows.map((r) => ({
    ts: Number(r.ts),
    pipeline: r.pipeline,
    source: r.source,
    stages: parseStages(r.stages),
    ok: Boolean(r.ok),
    latency_ms: Number(r.latency_ms),
    actor: r.actor,
    detail: r.detail,
  }));
  return NextResponse.json({ connected: true, events }, { headers: NO_STORE });
}
