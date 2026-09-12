/**
 * app/api/tickets/[id]/route.ts — single-ticket workflow operations.
 *
 * GET    /api/tickets/:id -> fetch one ticket            (200 / 404)
 * PUT    /api/tickets/:id -> transition / assign / note  (200 / 400 / 404 / 409)
 * DELETE /api/tickets/:id -> remove the ticket           (200 / 404)
 *
 * This is the only place a ticket's lifecycle may change. Every accepted mutation
 * appends to `history[]`, so the trail is complete and append-only: the fields
 * that describe the *evidence* (title, severity, source, device_id, finding_ref)
 * and the server-stamped fields (ticket_id, created_at, resolved_at) are rejected
 * here on purpose. Editing evidence after the fact is exactly what an audit trail
 * must not allow.
 *
 * The store is the in-memory demo registry in lib/store.ts and must be swapped
 * for D1 in production — see the note at the top of that file.
 */

import { NextResponse } from 'next/server';
import { requireAdmin } from '@/lib/auth';
import {
  apiError,
  boundedString,
  jsonResponse,
  methodNotAllowed,
  readJsonObject,
} from '@/lib/api';
import {
  getTicketStore,
  getValidTransitions,
  isValidTransition,
  isTicketStatus,
  logAudit,
  TICKET_ID_PATTERN,
  TICKET_STATUSES,
  type Ticket,
  type TicketHistoryEntry,
  type TicketStatus,
} from '@/lib/store';

export const dynamic = 'force-dynamic';

/** vinext passes route params as a thenable (Next.js 15 App Router semantics). */
type RouteContext = { params: Promise<{ id: string }> };

/** Methods this item resource really implements (used for the 405 Allow). */
const ALLOW = 'DELETE, GET, PUT';

const MAX_NOTE = 2_000;
const MAX_ASSIGNEE = 128;
const MAX_ACTOR = 128;

/** Actor recorded when a caller does not identify itself. */
const DEFAULT_ACTOR = 'aegis-console';

/** History verb recorded for each target status. */
const TRANSITION_ACTIONS: Readonly<Record<TicketStatus, string>> = {
  open: 'reopen',
  acknowledged: 'acknowledge',
  investigating: 'investigate',
  resolved: 'resolve',
  dismissed: 'dismiss',
};

/** States that close a ticket and therefore stamp `resolved_at`. */
const TERMINAL_STATUSES: readonly TicketStatus[] = ['resolved', 'dismissed'];

/** Everything PUT refuses to touch (see the file header for why). */
const NOT_EDITABLE = [
  'ticket_id',
  'title',
  'severity',
  'source',
  'device_id',
  'description',
  'finding_ref',
  'created_at',
  'updated_at',
  'resolved_at',
  'history',
] as const;

/** Optional `actor` override; defaults to the console's own identity. */
function readActor(value: unknown, problems: string[]): string {
  if (value === undefined || value === null) return DEFAULT_ACTOR;
  const actor = boundedString(value, MAX_ACTOR);
  if (actor === null) {
    problems.push(
      `actor must be a non-empty string of at most ${MAX_ACTOR} characters`,
    );
    return DEFAULT_ACTOR;
  }
  return actor;
}

/**
 * Resolves and validates the `:id` segment.
 * A malformed id is a bad request; a well-formed but unknown id is a 404.
 */
async function resolveTicket(
  context: RouteContext,
): Promise<{ ticket: Ticket } | { response: NextResponse }> {
  const { id } = await context.params;
  const ticketId = typeof id === 'string' ? id.trim() : '';

  if (!TICKET_ID_PATTERN.test(ticketId)) {
    return {
      response: apiError(
        'invalid_ticket_id',
        'Ticket ids look like TKT-YYYYMMDD-NNNN.',
        400,
        ['id must match TKT-\\d{8}-\\d{4}'],
      ),
    };
  }

  const ticket = getTicketStore().get(ticketId);
  if (!ticket) {
    return {
      response: apiError(
        'ticket_not_found',
        `No ticket with id ${ticketId}.`,
        404,
      ),
    };
  }
  return { ticket };
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

/** GET /api/tickets/:id — the ticket plus its full audit history. */
export async function GET(
  _request: Request,
  context: RouteContext,
): Promise<NextResponse> {
  const resolved = await resolveTicket(context);
  if ('response' in resolved) return resolved.response;
  return jsonResponse({ ticket: resolved.ticket });
}

/**
 * PUT /api/tickets/:id — advance the workflow.
 *
 * Body: `{ status?, assignee?, note?, actor? }` — at least one of the first three.
 * Each accepted change appends one entry to `history[]`; a status change and an
 * assignment in the same call append two, in that order.
 *
 * 409 (not 400) for a disallowed transition: the body is well formed, it simply
 * conflicts with the ticket's current state.
 */
export async function PUT(
  request: Request,
  context: RouteContext,
): Promise<NextResponse> {
  const resolved = await resolveTicket(context);
  if ('response' in resolved) return resolved.response;
  // Copy, never mutate in place: a rejected request must leave the store untouched.
  const ticket: Ticket = {
    ...resolved.ticket,
    history: [...resolved.ticket.history],
  };

  const parsed = await readJsonObject(request);
  if (!parsed.ok) return parsed.response;
  const body = parsed.value;

  const forbidden = NOT_EDITABLE.filter((field) => field in body);
  if (forbidden.length > 0) {
    return apiError(
      'read_only_field',
      'This endpoint only advances the workflow; ticket evidence and audit history are immutable.',
      400,
      forbidden.map((field) => `${field} cannot be modified here`),
    );
  }

  const problems: string[] = [];

  let nextStatus: TicketStatus | null = null;
  if ('status' in body) {
    if (!isTicketStatus(body.status)) {
      problems.push(
        `status must be one of ${TICKET_STATUSES.map((s) => `'${s}'`).join(', ')}`,
      );
    } else {
      nextStatus = body.status;
    }
  }

  let nextAssignee: string | null = null;
  if ('assignee' in body && body.assignee !== null) {
    const assignee = boundedString(body.assignee, MAX_ASSIGNEE);
    if (assignee === null) {
      problems.push(
        `assignee must be a non-empty string of at most ${MAX_ASSIGNEE} characters`,
      );
    } else {
      nextAssignee = assignee;
    }
  }

  let note: string | undefined;
  if ('note' in body && body.note !== null) {
    const text = boundedString(body.note, MAX_NOTE);
    if (text === null) {
      problems.push(
        `note must be a non-empty string of at most ${MAX_NOTE} characters`,
      );
    } else {
      note = text;
    }
  }

  const actor = readActor(body.actor, problems);

  if (problems.length > 0) {
    return apiError(
      'validation_failed',
      'Ticket update was rejected.',
      400,
      problems,
    );
  }
  if (nextStatus === null && nextAssignee === null && note === undefined) {
    return apiError(
      'no_updatable_fields',
      'Provide at least one of status, assignee or note.',
      400,
    );
  }

  // --- state machine (table owned by lib/store.ts) -------------------
  let transitioned = false;
  if (nextStatus !== null && nextStatus !== ticket.status) {
    if (!isValidTransition(ticket.status, nextStatus)) {
      return apiError(
        'invalid_status_transition',
        `A ticket cannot move from '${ticket.status}' to '${nextStatus}'.`,
        409,
        [
          `allowed next states from '${ticket.status}': ${getValidTransitions(
            ticket.status,
          )
            .map((state) => `'${state}'`)
            .join(', ')}`,
        ],
      );
    }
    transitioned = true;
  }

  // Acknowledging means owning: if nobody is assigned yet, the actor becomes the
  // assignee so an acknowledged ticket always has a responsible person.
  if (
    nextStatus === 'acknowledged' &&
    transitioned &&
    nextAssignee === null &&
    ticket.assignee === undefined
  ) {
    nextAssignee = actor;
  }

  const assigneeChanged =
    nextAssignee !== null && nextAssignee !== ticket.assignee;
  if (!transitioned && !assigneeChanged && note === undefined) {
    // Values supplied but already current — a no-op, reported honestly.
    return jsonResponse({ ticket, updated: false, changed: false });
  }

  const now = Date.now();
  const entries: TicketHistoryEntry[] = [];

  if (transitioned && nextStatus !== null) {
    ticket.status = nextStatus;
    entries.push({
      action: TRANSITION_ACTIONS[nextStatus],
      actor,
      timestamp: now,
      ...(note === undefined ? {} : { note }),
    });
    // Terminal states stamp resolved_at; reopening clears it so the ticket can be
    // closed again later with an accurate timestamp.
    if (TERMINAL_STATUSES.includes(nextStatus)) ticket.resolved_at = now;
    else delete ticket.resolved_at;
  }

  if (assigneeChanged && nextAssignee !== null) {
    ticket.assignee = nextAssignee;
    entries.push({
      action: 'assign',
      actor,
      timestamp: now,
      // The caller's note rides along with the primary action; the assignment
      // entry still says what changed.
      note:
        entries.length === 0 && note !== undefined
          ? note
          : `责任人变更为 ${nextAssignee}`,
    });
  }

  if (entries.length === 0 && note !== undefined) {
    entries.push({ action: 'comment', actor, timestamp: now, note });
  }

  ticket.history.push(...entries);
  ticket.updated_at = now;

  getTicketStore().set(ticket.ticket_id, ticket);

  // Audit trail: one entry per meaningful change (transition and/or assignment).
  if (transitioned && nextStatus !== null) {
    logAudit({
      actor,
      action: 'ticket:transition',
      resource_type: 'ticket',
      resource_id: ticket.ticket_id,
      detail: `工单状态 ${resolved.ticket.status} → ${nextStatus}${note ? `：${note}` : ''}。`,
    });
  }
  if (assigneeChanged && nextAssignee !== null) {
    logAudit({
      actor,
      action: 'ticket:assign',
      resource_type: 'ticket',
      resource_id: ticket.ticket_id,
      detail: `责任人变更为 ${nextAssignee}。`,
    });
  }

  return jsonResponse({ ticket, updated: true, changed: true });
}

/**
 * DELETE /api/tickets/:id — remove a ticket.
 *
 * Deleting is a registry operation, not a workflow transition, so it does not
 * append history: after the delete there is nothing left to read it. Real
 * deployments should prefer `dismissed` and reserve DELETE for bad data.
 */
export async function DELETE(
  _request: Request,
  context: RouteContext,
): Promise<NextResponse> {
  const resolved = await resolveTicket(context);
  if ('response' in resolved) return resolved.response;

  getTicketStore().delete(resolved.ticket.ticket_id);

  logAudit({
    actor: 'console_user',
    action: 'ticket:delete',
    resource_type: 'ticket',
    resource_id: resolved.ticket.ticket_id,
    detail: `删除工单「${resolved.ticket.title}」。`,
  });

  return jsonResponse({ deleted: true, ticket_id: resolved.ticket.ticket_id });
}

/**
 * POST / PATCH are not implemented on an individual ticket: creation happens on
 * the collection and partial edits are deliberately unsupported (see NOT_EDITABLE).
 * Exporting them keeps the 405 body JSON with `Cache-Control: no-store`.
 */
export function POST(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function PATCH(): NextResponse {
  return methodNotAllowed(ALLOW);
}
