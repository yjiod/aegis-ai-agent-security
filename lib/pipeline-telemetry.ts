import { pgEnabled, pgInsertPipelineEvent, pgLoadPipelineEvents, type PipelineEventRow } from './pg-store';

export interface PipelineStage {
  name: string;
  ok: boolean;
  detail?: string;
}

/**
 * 规则更新管道遥测（AIDR 可观测性）。真实活动记录：策略发布 / 基线同步 / 企业 MD
 * 发布在各自路由跑门禁后调用 recordPipelineEvent；无 PG（demo/未配置）时静默 no-op，
 * 读取返回 null → UI 诚实显示"暂无管道活动"，绝不伪造流水。
 */
export async function recordPipelineEvent(input: {
  pipeline: string;
  source: string;
  stages: PipelineStage[];
  ok: boolean;
  latencyMs: number;
  actor: string;
  detail?: string;
}): Promise<void> {
  if (!pgEnabled()) return;
  const row: PipelineEventRow = {
    ts: Math.floor(Date.now() / 1000),
    pipeline: input.pipeline,
    source: input.source,
    stages: JSON.stringify(input.stages),
    ok: input.ok,
    latency_ms: Math.max(0, Math.round(input.latencyMs)),
    actor: input.actor || 'system',
    detail: input.detail ?? '',
  };
  await pgInsertPipelineEvent(row);
}

export async function loadPipelineTelemetry(limit = 20): Promise<PipelineEventRow[] | null> {
  if (!pgEnabled()) return null;
  return pgLoadPipelineEvents(limit);
}

export function parseStages(raw: string): PipelineStage[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? (v as PipelineStage[]) : [];
  } catch {
    return [];
  }
}
