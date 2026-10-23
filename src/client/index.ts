import { toBase64 } from '../shared/base64.js';
import {
  type ChallengeResponse,
  clientDataFor,
  type ErrorCode,
  type FeedbackContext,
  type FeedbackPayload,
  type FeedbackResponse,
  type FeedbackType,
} from '../shared/protocol.js';

export interface ProveInput {
  clientData: string;
  clientDataHash: Uint8Array;
}

// the client half of a server Verifier: it turns client data into a proof object
export interface AttestProvider {
  readonly name: string;
  prove(input: ProveInput): Promise<Record<string, unknown>>;
  accepted?(): Promise<void>;
  rejected?(error: ErrorCode): Promise<void>;
}

export interface FeedbackClientOptions {
  // the feedback route; the challenge route is the same path plus /challenge
  endpoint: string;
  attest: AttestProvider;
  context?: FeedbackContext | (() => FeedbackContext | Promise<FeedbackContext>);
  fetch?: typeof fetch;
}

export interface SubmitInput {
  type: FeedbackType;
  text: string;
  screen?: string;
}

export type ClientErrorCode = ErrorCode | 'network' | 'attest_failed';

export type SubmitResult =
  { ok: true } | { ok: false; error: ClientErrorCode; message: string; retryAfterSeconds?: number };

export interface FeedbackClient {
  submit(input: SubmitInput): Promise<SubmitResult>;
}

class ClientError extends Error {
  constructor(
    readonly code: ClientErrorCode,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
  }
}

async function sha256(text: string): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return new Uint8Array(digest);
}

async function readResult(response: Response): Promise<FeedbackResponse> {
  try {
    return (await response.json()) as FeedbackResponse;
  } catch {
    return { ok: false, error: 'upstream_failed', message: `server answered ${response.status}` };
  }
}

async function payloadOf(
  input: SubmitInput,
  source: FeedbackClientOptions['context'],
): Promise<string> {
  const text = input.text.trim();
  if (text === '') throw new ClientError('bad_request', 'text is empty');
  const context = typeof source === 'function' ? await source() : source;
  const payload: FeedbackPayload = { type: input.type, text };
  if (input.screen !== undefined) payload.screen = input.screen;
  if (context !== undefined) payload.context = context;
  return JSON.stringify(payload);
}

export function createFeedbackClient(options: FeedbackClientOptions): FeedbackClient {
  const endpoint = options.endpoint.replace(/\/+$/, '');
  const doFetch = options.fetch ?? ((...args: Parameters<typeof fetch>) => fetch(...args));

  async function post(url: string, body: unknown): Promise<Response> {
    try {
      return await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (error) {
      throw new ClientError('network', (error as Error).message);
    }
  }

  async function challenge(): Promise<string> {
    const response = await post(`${endpoint}/challenge`, {});
    if (!response.ok) throw failureFrom(response, await readResult(response));
    return ((await response.json()) as ChallengeResponse).challenge;
  }

  async function proofFor(clientData: string): Promise<Record<string, unknown>> {
    try {
      return await options.attest.prove({ clientData, clientDataHash: await sha256(clientData) });
    } catch (error) {
      throw new ClientError('attest_failed', (error as Error).message);
    }
  }

  async function attempt(payload: string): Promise<FeedbackResponse> {
    const fresh = await challenge();
    const proof = await proofFor(clientDataFor(fresh, await sha256(payload)));
    const response = await post(endpoint, { payload, challenge: fresh, proof });
    const result = await readResult(response);
    if (!response.ok || !result.ok) throw failureFrom(response, result);
    return result;
  }

  async function submit(input: SubmitInput): Promise<SubmitResult> {
    try {
      const payload = await payloadOf(input, options.context);
      try {
        await attempt(payload);
      } catch (error) {
        // a server that has never seen this key, or has forgotten it, asks for a fresh attestation once
        if (!(error instanceof ClientError) || error.code !== 'unknown_key') throw error;
        await options.attest.rejected?.('unknown_key');
        await attempt(payload);
      }
      await options.attest.accepted?.();
      return { ok: true };
    } catch (error) {
      return toResult(error);
    }
  }

  return { submit };
}

function failureFrom(response: Response, result: FeedbackResponse): ClientError {
  const error = result.ok ? 'upstream_failed' : result.error;
  const message = result.ok ? `server answered ${response.status}` : result.message;
  const retry = Number(response.headers.get('retry-after'));
  return new ClientError(error, message, Number.isFinite(retry) && retry > 0 ? retry : undefined);
}

function toResult(error: unknown): SubmitResult {
  if (!(error instanceof ClientError)) throw error;
  const result: SubmitResult = { ok: false, error: error.code, message: error.message };
  if (error.retryAfterSeconds !== undefined) result.retryAfterSeconds = error.retryAfterSeconds;
  return result;
}

export { toBase64 };
export {
  type AppAttestBridge,
  type AppAttestState,
  type AppAttestStorage,
  createAppAttestProvider,
} from './app-attest.js';
