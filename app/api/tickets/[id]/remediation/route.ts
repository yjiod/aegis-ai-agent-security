import { NextResponse } from 'next/server';
import { getSession, requireAdmin } from '@/lib/auth';
import { apiError, boundedString, jsonResponse, readJsonObject } from '@/lib/api';
import { getTicketStore, logAudit, TICKET_ID_PATTERN, type Ticket } from '@/lib/store';

export const dynamic = 'force-dynamic';

/**
 * 审批绑定的修复闭环：建议(recommend) → 审批(approve) → 执行回执(receipt)。
 *
 * 不新增表/列：三个阶段以保留动词 `remediation:<phase>` 写入工单既有的 history
 * （已持久化 + 审计 + 时间线渲染）。强制「审批绑定」顺序——没有建议不能审批，
 * 没有审批不能记回执——让"推荐修复"必须经过人工审批与执行留痕，满足合规闭环。
 *
 * POST /api/tickets/:id/remediation  (admin)  body: { phase, note? }
 * GET  /api/tickets/:id/remediation  (任意已认证) -> 派生的当前闭环状态
 */

type RouteContext = { params: Promise<{ id: string }> };

const PHASES = ['recommend', 'approve', 'receipt'] as const;
type Phase = (typeof PHASES)[number];

const MAX_NOTE = 2_000;
const ACTION = (p: Phase) => `remediation:${p}`;

function isPhase(v: unknown): v is Phase {
  return typeof v === 'string' && (PHASES as readonly string[]).includes(v);
}

async function resolve(context: RouteContext): Promise<{ ticket: Ticket } | { response: NextResponse }> {
  const { id } = await context.params;
  const ticketId = typeof id === 'string' ? id.trim() : '';
  if (!TICKET_ID_PATTERN.test(ticketId)) {
    return { response: apiError('invalid_ticket_id', 'Ticket ids look like TKT-YYYYMMDD-NNNN.', 400, ['id must match TKT-\\d{8}-\\d{4}']) };
  }
  const ticket = getTicketStore().get(ticketId);
  if (!ticket) return { response: apiError('ticket_not_found', `No ticket with id ${ticketId}.`, 404) };
  return { ticket };
}

/** 取某阶段最近一条 history 记录（无则 null）。 */
function latestPhase(ticket: Ticket, phase: Phase) {
  const entries = (ticket.history ?? []).filter((h) => h.action === ACTION(phase));
  if (entries.length === 0) return null;
  return entries.reduce((a, b) => (b.timestamp >= a.timestamp ? b : a));
}

function remediationState(ticket: Ticket) {
  const recommend = latestPhase(ticket, 'recommend');
  const approve = latestPhase(ticket, 'approve');
  const receipt = latestPhase(ticket, 'receipt');
  const stage = receipt ? 'receipt' : approve ? 'approved' : recommend ? 'recommended' : 'none';
  return {
    stage,
    recommend: recommend ? { by: recommend.actor, at: recommend.timestamp, note: recommend.note ?? '' } : null,
    approve: approve ? { by: approve.actor, at: approve.timestamp, note: approve.note ?? '' } : null,
    receipt: receipt ? { by: receipt.actor, at: receipt.timestamp, note: receipt.note ?? '' } : null,
  };
}

export async function GET(request: Request, context: RouteContext) {
  const session = getSession(request);
  if (!session) return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  const resolved = await resolve(context);
  if ('response' in resolved) return resolved.response;
  return jsonResponse(remediationState(resolved.ticket));
}

export async function POST(request: Request, context: RouteContext) {
  const denied = requireAdmin(request);
  if (denied) return denied;
  const session = getSession(request);
  const actor = session?.subject ?? 'console';

  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  if (!isPhase(body.phase)) {
    return apiError('invalid_phase', `phase must be one of ${PHASES.join(', ')}.`, 400, ['phase is required']);
  }
  const phase = body.phase;

  const noteRaw = body.note === undefined || body.note === null ? '' : boundedString(body.note, MAX_NOTE);
  if (noteRaw === null) {
    return apiError('invalid_note', `note must be at most ${MAX_NOTE} characters.`, 400, ['note too long']);
  }
  const note = (noteRaw as string).trim();

  // 建议必须带内容；审批/回执可选但建议填写。
  if (phase === 'recommend' && !note) {
    return apiError('note_required', 'A remediation recommendation must include its content.', 400, ['note is required for recommend']);
  }

  const resolved = await resolve(context);
  if ('response' in resolved) return resolved.response;
  const ticket: Ticket = { ...resolved.ticket, history: [...resolved.ticket.history] };

  // 审批绑定顺序校验。
  if (phase === 'approve' && !latestPhase(ticket, 'recommend')) {
    return apiError('recommendation_required', 'Cannot approve before a remediation recommendation exists.', 409, ['add a recommendation first']);
  }
  if (phase === 'receipt' && !latestPhase(ticket, 'approve')) {
    return apiError('approval_required', 'Cannot record an execution receipt before approval.', 409, ['approve the recommendation first']);
  }

  const now = Date.now();
  ticket.history.push({ action: ACTION(phase), actor, timestamp: now, ...(note ? { note } : {}) });
  ticket.updated_at = now;
  getTicketStore().set(ticket.ticket_id, ticket);

  const phaseLabel = phase === 'recommend' ? '修复建议' : phase === 'approve' ? '修复审批' : '执行回执';
  logAudit({
    actor,
    action: 'ticket:remediation',
    resource_type: 'ticket',
    resource_id: ticket.ticket_id,
    detail: `${phaseLabel}${note ? `：${note}` : ''}`,
  });

  return jsonResponse({ ticket, remediation: remediationState(ticket), updated: true });
}
