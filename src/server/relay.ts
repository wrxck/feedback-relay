import { createHash } from 'node:crypto';

import { clientDataFor, type FeedbackPayload } from '../shared/protocol.js';
import { type ChallengeStore, createMemoryChallengeStore, issueChallenge } from './challenge.js';
import type { CreatedIssue, IssueSink } from './github.js';
import {
  failure,
  json,
  ok,
  readBody,
  type RelayRequest,
  type RelayResponse,
  RequestError,
} from './http.js';
import { buildIssue } from './issue.js';
import { createMemoryRateLimiter, type RateLimiter } from './rate-limit.js';
import { parseEnvelope, parsePayload } from './schema.js';
import type { Verifier } from './verifier.js';

export type RelayEvent =
  | { kind: 'rejected'; code: string; reason: string }
  | { kind: 'created'; issue: CreatedIssue }
  | { kind: 'failed'; error: unknown };

export interface FeedbackRelayOptions {
  verifier: Verifier;
  issues: IssueSink;
  challengeStore?: ChallengeStore;
  challengeTtlMs?: number;
  // counts challenge and feedback requests per client ip
  ipLimiter?: RateLimiter;
  // counts accepted proofs per verified subject, such as an app attest key
  subjectLimiter?: RateLimiter;
  maxBodyBytes?: number;
  maxTextLength?: number;
  extraLabels?: readonly string[];
  // rejection reasons go here, never to the client, so probing learns nothing
  onEvent?: (event: RelayEvent) => void;
  now?: () => number;
}

export interface FeedbackRelay {
  handleChallenge(request: Omit<RelayRequest, 'body'>): Promise<RelayResponse>;
  handleFeedback(request: RelayRequest): Promise<RelayResponse>;
}

const HOUR = 60 * 60 * 1000;

function sha256(text: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(text, 'utf8').digest());
}

function checkMethod(method: string | undefined): void {
  if (method !== undefined && method.toUpperCase() !== 'POST') {
    throw new RequestError('method_not_allowed', 'use POST');
  }
}

interface Settings {
  verifier: Verifier;
  issues: IssueSink;
  challenges: ChallengeStore;
  challengeTtlMs: number;
  ipLimiter: RateLimiter;
  subjects: RateLimiter;
  maxBodyBytes: number;
  maxTextLength: number;
  extraLabels: readonly string[];
  emit: (event: RelayEvent) => void;
  now: () => number;
}

function settingsFrom(options: FeedbackRelayOptions): Settings {
  return {
    verifier: options.verifier,
    issues: options.issues,
    challenges: options.challengeStore ?? createMemoryChallengeStore(),
    challengeTtlMs: options.challengeTtlMs ?? 2 * 60 * 1000,
    ipLimiter: options.ipLimiter ?? createMemoryRateLimiter({ max: 30, windowMs: HOUR }),
    subjects: options.subjectLimiter ?? createMemoryRateLimiter({ max: 10, windowMs: HOUR }),
    maxBodyBytes: options.maxBodyBytes ?? 64 * 1024,
    maxTextLength: options.maxTextLength ?? 4000,
    extraLabels: options.extraLabels ?? [],
    emit: options.onEvent ?? (() => undefined),
    now: options.now ?? Date.now,
  };
}

async function limit(s: Settings, limiter: RateLimiter, key: string): Promise<void> {
  const decision = await limiter.hit(key, s.now());
  if (!decision.allowed) {
    throw new RequestError('rate_limited', 'too many requests', decision.retryAfterMs);
  }
}

// cheap checks first, so junk never reaches the signature maths or the single-use challenge
async function prove(s: Settings, request: RelayRequest): Promise<FeedbackPayload> {
  checkMethod(request.method);
  const envelope = parseEnvelope(readBody(request.body, s.maxBodyBytes), s.maxBodyBytes);
  if (!envelope.ok) throw new RequestError('bad_request', envelope.reason);
  await limit(s, s.ipLimiter, `feedback:${request.ip ?? 'unknown'}`);
  const payload = parsePayload(envelope.value.payload, s.maxTextLength);
  if (!payload.ok) throw new RequestError('bad_request', payload.reason);
  const { challenge, proof } = envelope.value;
  if (!(await s.challenges.take(challenge, s.now()))) {
    throw new RequestError('bad_challenge', 'challenge is unknown, used or expired');
  }
  const clientData = clientDataFor(challenge, sha256(envelope.value.payload));
  const result = await s.verifier.verify({
    proof,
    clientData: new TextEncoder().encode(clientData),
    ip: request.ip,
  });
  if (!result.ok) throw new RequestError(result.code, result.reason);
  await limit(s, s.subjects, `${s.verifier.name}:${result.subject}`);
  return payload.value;
}

function reject(s: Settings, error: unknown): RelayResponse {
  if (!(error instanceof RequestError)) throw error;
  s.emit({ kind: 'rejected', code: error.code, reason: error.message });
  const shown = error.code === 'unverified' ? 'app proof was not accepted' : error.message;
  return failure(error.code, shown, error.retryAfterMs);
}

async function file(s: Settings, payload: FeedbackPayload): Promise<RelayResponse> {
  const draft = buildIssue(payload, {
    verifierName: s.verifier.name,
    extraLabels: s.extraLabels,
  });
  try {
    s.emit({ kind: 'created', issue: await s.issues.createIssue(draft) });
    return ok();
  } catch (error) {
    s.emit({ kind: 'failed', error });
    return failure('upstream_failed', 'the report could not be filed; try again later');
  }
}

export function createFeedbackRelay(options: FeedbackRelayOptions): FeedbackRelay {
  const s = settingsFrom(options);
  return {
    async handleFeedback(request) {
      let payload: FeedbackPayload;
      try {
        payload = await prove(s, request);
      } catch (error) {
        return reject(s, error);
      }
      return file(s, payload);
    },
    async handleChallenge(request) {
      try {
        checkMethod(request.method);
        await limit(s, s.ipLimiter, `challenge:${request.ip ?? 'unknown'}`);
      } catch (error) {
        return reject(s, error);
      }
      return json(200, await issueChallenge(s.challenges, s.challengeTtlMs, s.now()));
    },
  };
}
