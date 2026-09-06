import { NextResponse } from 'next/server';
import { getTicketStore, isValidTransition, type TicketStatus } from '@/lib/store';
import { invalidFieldPayload, maybeText, optionalText, requireText } from '@/lib/http-body';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(_request: Request, context: RouteContext) {
  const { id } = await context.params;
  const store = getTicketStore();
  const ticket = store.get(id);
  if (!ticket) return json({ error: 'ticket_not_found', ticket_id: id }, 404);
  return json({ ticket });
}

export async function PUT(request: Request, context: RouteContext) {
  const { id } = await context.params;
  const store = getTicketStore();
  const ticket = store.get(id);
  if (!ticket) return json({ error: 'ticket_not_found', ticket_id: id }, 404);

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  // 时间戳一律 epoch 毫秒（见 lib/store.ts 头部约定）。此前写秒会让 updated_at /
  // resolved_at / history.timestamp 与种子数据相差 1000 倍，客户端 timeAgo 失真。
  const now = Date.now();

  const wantsStatus = body.status !== undefined;
  const wantsAssignee = body.assignee !== undefined;

  let actor: string;
  let note: string | undefined;
  let rawStatus: string | undefined;
  let rawAssignee: string | undefined;
  try {
    actor = optionalText(body, 'actor', 'console_user').slice(0, 64);
    note = maybeText(body, 'note', 500);
    if (wantsStatus) rawStatus = requireText(body, 'status');
    if (wantsAssignee) rawAssignee = requireText(body, 'assignee').slice(0, 64) || undefined;
  } catch (error) {
    const payload = invalidFieldPayload(error);
    if (!payload) throw error;
    return json({ ...payload, hint: 'fields must be string/number/boolean, not object or array' }, 400);
  }

  // Status transition
  if (wantsStatus) {
    const newStatus = rawStatus as TicketStatus;
    const allStatuses: TicketStatus[] = ['open', 'acknowledged', 'investigating', 'resolved', 'dismissed'];
    if (!allStatuses.includes(newStatus)) {
      return json({ error: 'invalid_status', allowed: allStatuses }, 400);
    }
    if (!isValidTransition(ticket.status, newStatus)) {
      return json({
        error: 'invalid_transition',
        from: ticket.status,
        to: newStatus,
        hint: `Valid transitions from '${ticket.status}': see workflow rules`,
      }, 422);
    }
    // 必须在改写前留存来源状态：此前先赋 ticket.status 再拼历史动作，
    // 导致审计轨迹恒为 "status:resolved→resolved"，来源状态永久丢失。
    const fromStatus = ticket.status;
    ticket.status = newStatus;
    ticket.updated_at = now;
    if (newStatus === 'resolved' || newStatus === 'dismissed') ticket.resolved_at = now;
    if (newStatus === 'open') ticket.resolved_at = undefined;
    ticket.history.push({ action: `status:${fromStatus}→${newStatus}`, actor, timestamp: now, note });
  }

  // Assignee update
  if (wantsAssignee) {
    ticket.assignee = rawAssignee;
    ticket.updated_at = now;
    ticket.history.push({
      action: 'assigned',
      actor,
      timestamp: now,
      note: ticket.assignee ? `指派给 ${ticket.assignee}` : '取消指派',
    });
  }

  store.set(id, ticket);
  return json({ ticket });
}

export async function DELETE(_request: Request, context: RouteContext) {
  const { id } = await context.params;
  const store = getTicketStore();
  if (!store.has(id)) return json({ error: 'ticket_not_found', ticket_id: id }, 404);
  store.delete(id);
  return json({ deleted: true, ticket_id: id });
}
