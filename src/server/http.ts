import type { ErrorCode, FeedbackResponse } from '../shared/protocol.js';

export interface RelayRequest {
  method?: string | undefined;
  // the raw body, or an object a framework has already parsed from json
  body: unknown;
  // the client address as your proxy setup reports it; used only for rate limiting
  ip?: string | undefined;
}

export interface RelayResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

const STATUS: Record<ErrorCode, number> = {
  method_not_allowed: 405,
  too_large: 413,
  bad_request: 400,
  rate_limited: 429,
  bad_challenge: 401,
  unverified: 401,
  unknown_key: 401,
  upstream_failed: 502,
};

export function json(status: number, value: unknown, extra: Record<string, string> = {}) {
  return {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra },
    body: JSON.stringify(value),
  } satisfies RelayResponse;
}

export function ok(): RelayResponse {
  const value: FeedbackResponse = { ok: true };
  return json(201, value);
}

export function failure(error: ErrorCode, message: string, retryAfterMs?: number): RelayResponse {
  const value: FeedbackResponse = { ok: false, error, message };
  const extra: Record<string, string> =
    retryAfterMs === undefined ? {} : { 'retry-after': String(Math.ceil(retryAfterMs / 1000)) };
  return json(STATUS[error], value, extra);
}

export class RequestError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly retryAfterMs?: number,
  ) {
    super(message);
  }
}

// a string or bytes body is size checked here; a pre-parsed object relies on the framework's limit
export function readBody(body: unknown, maxBytes: number): unknown {
  if (body === undefined || body === null) throw new RequestError('bad_request', 'body is empty');
  if (typeof body !== 'string' && !(body instanceof Uint8Array)) return body;
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  if (bytes.length > maxBytes)
    throw new RequestError('too_large', `body exceeds ${maxBytes} bytes`);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new RequestError('bad_request', 'body is not valid utf-8 json');
  }
}
