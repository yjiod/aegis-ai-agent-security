import { NextResponse } from 'next/server';
import { requireAdmin, getSession } from '@/lib/auth';
import { syncUpstream } from '@/lib/baselines';
import { recordPipelineEvent } from '@/lib/pipeline-telemetry';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** POST /api/baselines/sync — 从上游 URL 拉取基线(admin)。body:{url}；并记录管道遥测。 */
export async function POST(request: Request) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  const t0 = Date.now();
  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return NextResponse.json({ error: 'invalid_json' }, { status: 400, headers: NO_STORE }); }
  const url = String(body.url ?? '').trim();
  if (!/^https?:\/\//.test(url)) return NextResponse.json({ error: 'invalid_url' }, { status: 400, headers: NO_STORE });
  try {
    const b = await syncUpstream(url, session?.subject ?? 'console');
    void recordPipelineEvent({
      pipeline: 'baseline-sync',
      source: url,
      stages: [
        { name: '拉取', ok: true },
        { name: '结构验证', ok: true, detail: `${b.rules.length} rules` },
        { name: '发布', ok: true, detail: `v${b.version}` },
      ],
      ok: true,
      latencyMs: Date.now() - t0,
      actor: session?.subject ?? 'console',
      detail: `${b.name} v${b.version}`,
    }).catch(() => {});
    return NextResponse.json({ baseline: { name: b.name, version: b.version, rules: b.rules.length } }, { headers: NO_STORE });
  } catch (e) {
    const reason = e instanceof Error ? e.message : 'sync_failed';
    void recordPipelineEvent({
      pipeline: 'baseline-sync',
      source: url,
      stages: [
        { name: '拉取/结构验证', ok: false, detail: reason },
        { name: '发布', ok: false, detail: 'aborted' },
      ],
      ok: false,
      latencyMs: Date.now() - t0,
      actor: session?.subject ?? 'console',
      detail: reason,
    }).catch(() => {});
    return NextResponse.json({ error: reason }, { status: 502, headers: NO_STORE });
  }
}
