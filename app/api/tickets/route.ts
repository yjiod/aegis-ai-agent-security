import { NextResponse } from 'next/server';
import { getTicketStore, nextTicketId, type Ticket } from '@/lib/store';

export const dynamic = 'force-dynamic';

const HEADERS = { 'Cache-Control': 'no-store' };
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const STATUSES = ['open', 'acknowledged', 'investigating', 'resolved', 'dismissed'] as const;

function json(data: unknown, status = 200) {
  return NextResponse.json(data, { status, headers: HEADERS });
}

export async function GET(request: Request) {
  const store = getTicketStore();
  const url = new URL(request.url);
  const statusFilter = url.searchParams.get('status');
  const severityFilter = url.searchParams.get('severity');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? 50), 200);
  const offset = Number(url.searchParams.get('offset') ?? 0);

  let tickets = [...store.values()];
  if (statusFilter && STATUSES.includes(statusFilter as typeof STATUSES[number])) {
    tickets = tickets.filter((t) => t.status === statusFilter);
  }
  if (severityFilter && SEVERITIES.includes(severityFilter as typeof SEVERITIES[number])) {
    tickets = tickets.filter((t) => t.severity === severityFilter);
  }

  tickets.sort((a, b) => b.updated_at - a.updated_at);
  const total = tickets.length;
  const paged = tickets.slice(offset, offset + limit);
  return json({ tickets: paged, total, limit, offset });
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const title = String(body.title ?? '').trim();
  const severity = String(body.severity ?? 'medium');
  const source = String(body.source ?? '').trim();
  const device_id = String(body.device_id ?? '').trim();
  const description = body.description ? String(body.description).slice(0, 2000) : undefined;
  const finding_ref = body.finding_ref ? String(body.finding_ref).slice(0, 64) : undefined;

  if (!title || title.length > 200) return json({ error: 'invalid_title', hint: '1-200 chars required' }, 400);
  if (!SEVERITIES.includes(severity as typeof SEVERITIES[number])) return json({ error: 'invalid_severity', allowed: SEVERITIES }, 400);
  if (!source || source.length > 128) return json({ error: 'invalid_source' }, 400);
  if (!device_id || device_id.length > 64) return json({ error: 'invalid_device_id' }, 400);

  const now = Math.floor(Date.now() / 1000);
  const ticket: Ticket = {
    ticket_id: nextTicketId(),
    title,
    severity: severity as Ticket['severity'],
    status: 'open',
    source,
    device_id,
    description,
    finding_ref,
    created_at: now,
    updated_at: now,
    history: [{ action: 'created', actor: 'console_user', timestamp: now, note: '通过控制台手动创建' }],
  };

  const store = getTicketStore();
  store.set(ticket.ticket_id, ticket);
  return json({ ticket }, 201);
}
