import { NextResponse } from 'next/server';
import { getTicketStore, nextTicketId, type Ticket } from '@/lib/store';
import { invalidFieldPayload, maybeText, optionalText } from '@/lib/http-body';

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

  let title: string;
  let severity: string;
  let source: string;
  let device_id: string;
  let description: string | undefined;
  let finding_ref: string | undefined;
  try {
    title = optionalText(body, 'title', '').trim();
    severity = optionalText(body, 'severity', 'medium');
    source = optionalText(body, 'source', '').trim();
    device_id = optionalText(body, 'device_id', '').trim();
    description = maybeText(body, 'description', 2000);
    finding_ref = maybeText(body, 'finding_ref', 64);
  } catch (error) {
    const payload = invalidFieldPayload(error);
    if (!payload) throw error;
    return json({ ...payload, hint: 'fields must be string/number/boolean, not object or array' }, 400);
  }

  if (!title || title.length > 200) return json({ error: 'invalid_title', hint: '1-200 chars required' }, 400);
  if (!SEVERITIES.includes(severity as typeof SEVERITIES[number])) return json({ error: 'invalid_severity', allowed: SEVERITIES }, 400);
  if (!source || source.length > 128) return json({ error: 'invalid_source' }, 400);
  if (!device_id || device_id.length > 64) return json({ error: 'invalid_device_id' }, 400);

  // 时间戳一律 epoch 毫秒（见 lib/store.ts 头部约定）。此前误写为秒，会让新建
  // 工单的 created_at 与种子数据相差 1000 倍：排序恒为最旧、ticketDay() 落到
  // 1970、客户端 timeAgo() 失真。
  const now = Date.now();
  // nextTicketId 需要现存 store 才能算出当日序号（TKT-YYYYMMDD-NNNN），
  // 因此必须先取 store 再分配 id —— 此前无参调用会在 store.keys() 上抛 TypeError。
  const store = getTicketStore();
  const ticket: Ticket = {
    ticket_id: nextTicketId(store, now),
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

  store.set(ticket.ticket_id, ticket);
  return json({ ticket }, 201);
}
