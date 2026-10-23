import { failure, type RelayResponse } from './http.js';
import type { FeedbackRelay } from './relay.js';

// duck types: express is never imported, so plain node:http request and response objects work too
export interface NodeLikeRequest extends Partial<AsyncIterable<unknown>> {
  method?: string | undefined;
  body?: unknown;
  ip?: string;
  socket?: { remoteAddress?: string | undefined };
}

export interface NodeLikeResponse {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

export type NodeHandler = (
  req: NodeLikeRequest,
  res: NodeLikeResponse,
  next?: (error?: unknown) => void,
) => Promise<void>;

export interface ExpressAdapterOptions {
  // must match the relay's maxBodyBytes when no body parser runs before the handler
  maxBodyBytes?: number;
}

class TooLarge extends Error {}

const TOO_LARGE = Symbol('too large');

async function readStream(req: AsyncIterable<unknown>, maxBytes: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of req) {
    const bytes =
      typeof chunk === 'string' ? new TextEncoder().encode(chunk) : (chunk as Uint8Array);
    size += bytes.length;
    if (size > maxBytes) throw new TooLarge();
    chunks.push(bytes);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

// a framework body parser wins; otherwise the raw stream is read here with the same size cap
async function bodyOf(req: NodeLikeRequest, maxBytes: number): Promise<unknown> {
  if (req.body !== undefined) return req.body;
  if (!req[Symbol.asyncIterator]) return undefined;
  try {
    return await readStream(req as AsyncIterable<unknown>, maxBytes);
  } catch (error) {
    if (error instanceof TooLarge) return TOO_LARGE;
    throw error;
  }
}

function send(res: NodeLikeResponse, response: RelayResponse): void {
  res.statusCode = response.status;
  for (const [name, value] of Object.entries(response.headers)) res.setHeader(name, value);
  res.end(response.body);
}

function wrap(run: (req: NodeLikeRequest) => Promise<RelayResponse>): NodeHandler {
  return async (req, res, next) => {
    try {
      send(res, await run(req));
    } catch (error) {
      if (next) {
        next(error);
        return;
      }
      res.statusCode = 500;
      res.end();
    }
  };
}

// set express's "trust proxy" correctly, or every client behind your proxy shares one ip bucket
function ipOf(req: NodeLikeRequest): string | undefined {
  return req.ip ?? req.socket?.remoteAddress;
}

export function expressHandlers(
  relay: FeedbackRelay,
  options: ExpressAdapterOptions = {},
): { challenge: NodeHandler; feedback: NodeHandler } {
  const maxBytes = options.maxBodyBytes ?? 64 * 1024;
  return {
    challenge: wrap((req) => relay.handleChallenge({ method: req.method, ip: ipOf(req) })),
    feedback: wrap(async (req) => {
      const body = await bodyOf(req, maxBytes);
      if (body === TOO_LARGE) return failure('too_large', `body exceeds ${maxBytes} bytes`);
      return relay.handleFeedback({ method: req.method, body, ip: ipOf(req) });
    }),
  };
}
