import { toBase64Url } from './base64.js';

export const PROTOCOL_VERSION = 'feedback-relay/v1';

export type FeedbackType = 'bug' | 'idea';

// only coarse, non-identifying facts about the app; the server rejects any other field
export interface FeedbackContext {
  appVersion?: string;
  build?: string;
  os?: string;
  osVersion?: string;
  locale?: string;
}

export interface FeedbackPayload {
  type: FeedbackType;
  text: string;
  screen?: string;
  context?: FeedbackContext;
}

// payload stays a string so both sides hash the exact same bytes without canonical json
export interface FeedbackEnvelope {
  payload: string;
  challenge: string;
  proof: Record<string, unknown>;
}

export interface ChallengeResponse {
  challenge: string;
  expiresAt: number;
}

export type ErrorCode =
  | 'method_not_allowed'
  | 'too_large'
  | 'bad_request'
  | 'rate_limited'
  | 'bad_challenge'
  | 'unverified'
  | 'unknown_key'
  | 'upstream_failed';

export type FeedbackResponse = { ok: true } | { ok: false; error: ErrorCode; message: string };

// the string the app proof signs: it binds one server challenge to one exact payload
export function clientDataFor(challenge: string, payloadSha256: Uint8Array): string {
  return `${PROTOCOL_VERSION}|${challenge}|${toBase64Url(payloadSha256)}`;
}
