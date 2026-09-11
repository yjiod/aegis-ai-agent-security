/**
 * lib/api.ts — small HTTP + validation helpers shared by the /api/devices and
 * /api/tickets route groups.
 *
 * Every response is JSON and carries `Cache-Control: no-store`. Governance data
 * (device inventory, risk tickets) must never be cached by the browser, a CDN,
 * or the Workers runtime, and error bodies follow the same flat
 * `{ error, message, details? }` shape already used by app/api/summary/route.ts.
 */

import { NextResponse } from 'next/server';

/** Hard cap on request bodies; device/ticket metadata is tiny by design. */
export const MAX_BODY_BYTES = 16_384;

export interface ApiErrorBody {
  /** Stable snake_case code clients can branch on. */
  error: string;
  message: string;
  /** Per-field problems, present only for validation failures. */
  details?: string[];
}

/** JSON response with the no-store policy applied. */
export function jsonResponse<T>(body: T, status = 200): NextResponse {
  return NextResponse.json(body, {
    status,
    headers: { 'Cache-Control': 'no-store' },
  });
}

/** Structured error response. `details` is omitted when empty. */
export function apiError(
  code: string,
  message: string,
  status: number,
  details?: readonly string[],
): NextResponse {
  return jsonResponse<ApiErrorBody>(
    {
      error: code,
      message,
      ...(details && details.length > 0 ? { details: [...details] } : {}),
    },
    status,
  );
}

/**
 * 405 with a JSON body and an accurate `Allow` header.
 *
 * vinext/Next.js already answers unexported methods with a bare 405 and an empty
 * body; the routes export these stubs so clients always get the same JSON error
 * envelope plus the no-store policy.
 */
export function methodNotAllowed(allow: string): NextResponse {
  const response = apiError(
    'method_not_allowed',
    `This endpoint supports: ${allow}.`,
    405,
  );
  response.headers.set('Allow', allow);
  return response;
}

/* ------------------------------------------------------------------ *
 * Request body parsing
 * ------------------------------------------------------------------ */

export type BodyResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; response: NextResponse };

const TOO_LARGE = Symbol('too_large');

/**
 * Streams the body and enforces `limit` byte-by-byte, so an oversized payload is
 * rejected without ever being buffered in full. Mirrors the bounded reader in
 * app/api/summary/route.ts.
 */
async function readBoundedText(
  request: Request,
  limit: number,
): Promise<string | typeof TOO_LARGE> {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (Number.isSafeInteger(declared) && declared > limit) return TOO_LARGE;
  if (!request.body) return '';

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        return TOO_LARGE;
      }
      chunks.push(value);
    }
  } catch {
    await reader.cancel().catch(() => undefined);
    throw new Error('request body unreadable');
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/**
 * Parses a request body that must be a single JSON object.
 * Returns `{ ok: false, response }` with the right status for every failure
 * mode (413 / 400), so callers can forward the response directly.
 */
export async function readJsonObject(
  request: Request,
  limit = MAX_BODY_BYTES,
): Promise<BodyResult> {
  let text: string | typeof TOO_LARGE;
  try {
    text = await readBoundedText(request, limit);
  } catch {
    return {
      ok: false,
      response: apiError(
        'unreadable_body',
        'Request body could not be read.',
        400,
      ),
    };
  }

  if (text === TOO_LARGE) {
    return {
      ok: false,
      response: apiError(
        'payload_too_large',
        `Request body must not exceed ${limit} bytes.`,
        413,
      ),
    };
  }
  if (text.length === 0) {
    return {
      ok: false,
      response: apiError('empty_body', 'A JSON request body is required.', 400),
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      ok: false,
      response: apiError(
        'invalid_json',
        'Request body is not valid UTF-8 JSON.',
        400,
      ),
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      ok: false,
      response: apiError(
        'invalid_body',
        'Request body must be a single JSON object.',
        400,
      ),
    };
  }
  return { ok: true, value: parsed as Record<string, unknown> };
}

/* ------------------------------------------------------------------ *
 * Field validation primitives
 * ------------------------------------------------------------------ */

/** Trimmed, non-empty string of at most `max` characters, else null. */
export function boundedString(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) return null;
  return trimmed;
}

/**
 * Version-ish token (e.g. `v3.8`, `0.30.0`, `4.8.0-rc1`). Deliberately narrow:
 * versions are echoed into UI and logs, so no spaces or shell metacharacters.
 */
export function boundedVersion(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  return /^[A-Za-z0-9._+-]{1,64}$/.test(value) ? value : null;
}

/** Non-negative safe integer, else null. Used for epoch-millisecond fields. */
export function boundedTimestamp(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    return null;
  }
  return value;
}

/**
 * Integer query parameter with an explicit range.
 * Absent/empty -> `fallback`; malformed or out of range -> null so the caller
 * can answer 400 rather than silently clamping.
 */
export function intParam(
  searchParams: URLSearchParams,
  key: string,
  fallback: number,
  min: number,
  max: number,
): number | null {
  const raw = searchParams.get(key);
  if (raw === null || raw === '') return fallback;
  if (!/^\d{1,9}$/.test(raw)) return null;
  const value = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(value) || value < min || value > max) return null;
  return value;
}
