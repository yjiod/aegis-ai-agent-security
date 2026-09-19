/**
 * app/api/evidence/route.ts — 审计/证据导出包生成（aegis.evidence/v1）。
 *
 * GET /api/evidence?device_id=&since=&until=&sections=&redaction=
 *   -> 组装并 ed25519 签名的单个 JSON 证据包（附件下载）。
 *
 * 权限：审计员/管理员（requireAuditor）。verbose 脱敏级别仅管理员可用。
 * 每次生成都写一条 `evidence:export` 审计（谁、何时、范围、脱敏级别、各 section
 * 行数、整包 sha256），使"导出证据"这件事本身也在审计链里、且会出现在下一次的包里。
 *
 * 只读：本路由不改变任何治理状态（除追加一条导出审计）。
 */

import { NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { requireAuditor, getSession } from '@/lib/auth';
import { DEVICE_ID_PATTERN, logAudit } from '@/lib/store';
import { canonicalJson } from '@/lib/policy';
import { apiError, jsonResponse } from '@/lib/api';
import {
  buildEvidenceBundle,
  EVIDENCE_SECTIONS,
  type EvidenceSection,
  type RedactionLevel,
} from '@/lib/evidence';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' } as const;

/** epoch-ms 时间戳解析（13 位）；缺省→null，非法→'bad'。 */
function parseMs(raw: string | null): number | null | 'bad' {
  if (raw === null || raw === '') return null;
  if (!/^\d{1,14}$/.test(raw)) return 'bad';
  const n = Number.parseInt(raw, 10);
  return Number.isSafeInteger(n) && n >= 0 ? n : 'bad';
}

function parseSections(raw: string | null): EvidenceSection[] | 'bad' {
  if (raw === null || raw.trim() === '') return [...EVIDENCE_SECTIONS];
  const seen = new Set<EvidenceSection>();
  for (const part of raw.split(',')) {
    const trimmed = part.trim();
    if (trimmed === '') continue;
    if (!(EVIDENCE_SECTIONS as readonly string[]).includes(trimmed)) return 'bad';
    seen.add(trimmed as EvidenceSection);
  }
  return seen.size > 0 ? [...seen] : 'bad';
}

function bundleSha256(bundle: Record<string, unknown>): string {
  const core: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(bundle)) {
    if (!['ed25519_signature', 'ed25519_public', 'ed25519_key_id'].includes(k)) core[k] = v;
  }
  return createHash('sha256').update(canonicalJson(core)).digest('hex');
}

function filename(scopeDevice: string | null, at: number): string {
  const d = new Date(at);
  const pad = (n: number) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  return `aegis-evidence-${scopeDevice ?? 'fleet'}-${stamp}.json`;
}

export async function GET(request: Request): Promise<NextResponse> {
  const denied = requireAuditor(request);
  if (denied) return denied;
  const session = getSession(request);
  const actor = session?.subject ?? 'auditor';
  const isAdmin = session?.role === 'admin';

  const url = new URL(request.url);
  const problems: string[] = [];

  const deviceIdRaw = url.searchParams.get('device_id');
  let deviceId: string | null = null;
  if (deviceIdRaw !== null && deviceIdRaw.trim() !== '') {
    const trimmed = deviceIdRaw.trim();
    if (!DEVICE_ID_PATTERN.test(trimmed)) problems.push('device_id must be 3-64 characters of [A-Za-z0-9-]');
    else deviceId = trimmed;
  }

  const since = parseMs(url.searchParams.get('since'));
  const until = parseMs(url.searchParams.get('until'));
  if (since === 'bad') problems.push('since must be a non-negative epoch-ms integer');
  if (until === 'bad') problems.push('until must be a non-negative epoch-ms integer');
  if (typeof since === 'number' && typeof until === 'number' && since > until) problems.push('since must not be after until');

  const sections = parseSections(url.searchParams.get('sections'));
  if (sections === 'bad') problems.push(`sections must be a comma list of ${EVIDENCE_SECTIONS.join(', ')}`);

  const redactionRaw = url.searchParams.get('redaction') ?? 'standard';
  const redactionOk = redactionRaw === 'standard' || redactionRaw === 'verbose';
  const redaction: RedactionLevel = redactionRaw === 'verbose' ? 'verbose' : 'standard';
  if (!redactionOk) problems.push("redaction must be 'standard' or 'verbose'");
  // verbose 保留运维细节（真实路径/IP/os_user），仅管理员可用；secret 仍恒打码。
  if (redactionRaw === 'verbose' && !isAdmin) problems.push('redaction=verbose requires admin role');

  if (problems.length > 0 || sections === 'bad' || since === 'bad' || until === 'bad') {
    return apiError('validation_failed', 'Evidence export was rejected.', 400, problems);
  }

  const bundle = await buildEvidenceBundle({
    actor,
    deviceId,
    since: typeof since === 'number' ? since : null,
    until: typeof until === 'number' ? until : null,
    sections: sections as EvidenceSection[],
    redaction,
    consoleVersion: process.env.AEGIS_CONSOLE_VERSION ?? '',
  });

  const sha = bundleSha256(bundle as unknown as Record<string, unknown>);
  const counts = Object.fromEntries(Object.entries(bundle.manifest).map(([k, v]) => [k, v.count]));
  logAudit({
    actor,
    action: 'evidence:export',
    resource_type: 'system',
    detail: `scope=${deviceId ?? 'fleet'} redaction=${redaction} sections=${(sections as EvidenceSection[]).join('+')} counts=${JSON.stringify(counts)} sha256=${sha}`,
  });

  const body = JSON.stringify(bundle, null, 2);
  return new NextResponse(body, {
    headers: {
      ...NO_STORE,
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="${filename(deviceId, bundle.generated_at)}"`,
    },
  });
}

/** 只支持 GET（生成/下载）。 */
export function POST(): NextResponse {
  return jsonResponse({ error: 'method_not_allowed', message: 'Use GET to generate an evidence bundle; POST /api/evidence/verify to verify one.' }, 405);
}
