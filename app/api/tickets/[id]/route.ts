import { NextResponse } from 'next/server';
import { getTicketStore, isValidTransition, type TicketStatus } from '@/lib/store';

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

  const now = Math.floor(Date.now() / 1000);
  const actor = String(body.actor ?? 'console_user').slice(0, 64);
  const note = body.note ? String(body.note).slice(0, 500) : undefined;

  // Status transition
  if (body.status !== undefined) {
    const newStatus = String(body.status) as TicketStatus;
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
    ticket.status = newStatus;
    ticket.updated_at = now;
    if (newStatus === 'resolved' || newStatus === 'dismissed') ticket.resolved_at = now;
    if (newStatus === 'open') ticket.resolved_at = undefined;
    ticket.history.push({ action: `status:${ticket.status}→${newStatus}`, actor, timestamp: now, note });
  }

  // Assignee update
  if (body.assignee !== undefined) {
    ticket.assignee = String(body.assignee).slice(0, 64) || undefined;
    ticket.updated_at = now;
    ticket.history.push({ action: 'assigned', actor, timestamp: now, note: `指派给 ${ticket.assignee}` });
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
