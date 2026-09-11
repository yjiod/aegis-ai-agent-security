/**
 * app/api/audit/route.ts — read-only audit trail for the Aegis console.
 *
 * GET /api/audit?limit=50&offset=0&resource_type=device|ticket|policy|system&action=create|update|delete|transition
 *   -> { entries: AuditEntry[], total: number, returned: number, limit: number, offset: number }
 *
 * Entries are returned newest-first. `total` is the post-filter count so a client
 * can page without a second request. Backed for now by the in-memory audit store
 * in lib/store.ts (`getAuditStore`); swap in `d1ListAudit` from lib/d1-store.ts
 * when the console runs against a D1 binding.
 *
 * Mutations are recorded by the device/ticket routes via `logAudit`; this route
 * only ever reads. Like every /api response it carries `Cache-Control: no-store`
 * (applied by `jsonResponse`).
 */

import { NextResponse } from 'next/server';
import { apiError, intParam, jsonResponse, methodNotAllowed } from '@/lib/api';
import {
  AUDIT_RESOURCE_TYPES,
  getAuditStore,
  isAuditResourceType,
  type AuditEntry,
} from '@/lib/store';

export const dynamic = 'force-dynamic';

/** This resource only implements GET. */
const ALLOW = 'GET';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const MAX_OFFSET = 100_000;

/** Newest first; ties broken by id so paging is stable. */
function compareEntries(left: AuditEntry, right: AuditEntry): number {
  if (left.timestamp !== right.timestamp) return right.timestamp - left.timestamp;
  return right.id - left.id;
}

/**
 * The `action` filter accepts a bare verb ('create') or a namespaced one
 * ('device:create'); a bare verb matches any resource with that trailing segment.
 */
function matchesAction(entry: AuditEntry, action: string): boolean {
  if (entry.action === action) return true;
  return entry.action.endsWith(`:${action}`);
}

export async function GET(request: Request): Promise<NextResponse> {
  const searchParams = new URL(request.url).searchParams;
  const problems: string[] = [];

  const limit = intParam(searchParams, 'limit', DEFAULT_LIMIT, 1, MAX_LIMIT);
  if (limit === null) {
    problems.push(`limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  const offset = intParam(searchParams, 'offset', 0, 0, MAX_OFFSET);
  if (offset === null) {
    problems.push(`offset must be an integer between 0 and ${MAX_OFFSET}`);
  }

  const rawResourceType = searchParams.get('resource_type');
  let resourceType: string | null = null;
  if (rawResourceType !== null && rawResourceType !== '') {
    const trimmed = rawResourceType.trim();
    if (!isAuditResourceType(trimmed)) {
      problems.push(
        `resource_type must be one of ${AUDIT_RESOURCE_TYPES.map((t) => `'${t}'`).join(', ')}`,
      );
    } else {
      resourceType = trimmed;
    }
  }

  const rawAction = searchParams.get('action');
  const action =
    rawAction !== null && rawAction.trim() !== '' ? rawAction.trim() : null;

  if (problems.length > 0 || limit === null || offset === null) {
    return apiError('validation_failed', 'Audit query was rejected.', 400, problems);
  }

  const filtered = getAuditStore()
    .filter((entry) => (resourceType === null ? true : entry.resource_type === resourceType))
    .filter((entry) => (action === null ? true : matchesAction(entry, action)))
    .sort(compareEntries);

  const page = filtered.slice(offset, offset + limit);

  return jsonResponse({
    entries: page,
    total: filtered.length,
    returned: page.length,
    limit,
    offset,
  });
}

/** The audit trail is read-only over HTTP; mutations are logged server-side. */
export function POST(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function PUT(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function DELETE(): NextResponse {
  return methodNotAllowed(ALLOW);
}

export function PATCH(): NextResponse {
  return methodNotAllowed(ALLOW);
}
