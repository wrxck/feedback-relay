import type {
  FeedbackContext,
  FeedbackEnvelope,
  FeedbackPayload,
  FeedbackType,
} from '../shared/protocol.js';
import { CHALLENGE_PATTERN } from './challenge.js';

type Result<T> = { ok: true; value: T } | { ok: false; reason: string };

const TYPES: readonly FeedbackType[] = ['bug', 'idea'];

// each context field is a short token; free text here would be a side door for personal data
const CONTEXT_FIELDS: Record<keyof FeedbackContext, RegExp> = {
  appVersion: /^[A-Za-z0-9._+-]{1,32}$/,
  build: /^[A-Za-z0-9._+-]{1,32}$/,
  os: /^[A-Za-z0-9 ._-]{1,32}$/,
  osVersion: /^[A-Za-z0-9._-]{1,32}$/,
  locale: /^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8}){0,3}$/,
};

const SCREEN = /^[A-Za-z0-9 _./:-]{1,80}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function unknownKey(
  value: Record<string, unknown>,
  allowed: readonly string[],
): string | undefined {
  return Object.keys(value).find((key) => !allowed.includes(key));
}

function fail<T>(reason: string): Result<T> {
  return { ok: false, reason };
}

export function parseEnvelope(value: unknown, maxPayloadLength: number): Result<FeedbackEnvelope> {
  if (!isRecord(value)) return fail('body is not a json object');
  const extra = unknownKey(value, ['payload', 'challenge', 'proof']);
  if (extra !== undefined) return fail(`unexpected field ${extra}`);
  const { payload, challenge, proof } = value;
  if (typeof payload !== 'string') return fail('payload must be a json string');
  if (payload.length > maxPayloadLength) return fail('payload is too long');
  if (typeof challenge !== 'string' || !CHALLENGE_PATTERN.test(challenge)) {
    return fail('challenge is malformed');
  }
  if (!isRecord(proof)) return fail('proof must be an object');
  return { ok: true, value: { payload, challenge, proof } };
}

function parseContext(value: unknown): Result<FeedbackContext> {
  if (!isRecord(value)) return fail('context must be an object');
  const context: FeedbackContext = {};
  for (const [key, field] of Object.entries(value)) {
    if (!Object.hasOwn(CONTEXT_FIELDS, key)) return fail(`unexpected context field ${key}`);
    const pattern = CONTEXT_FIELDS[key as keyof FeedbackContext];
    if (typeof field !== 'string' || !pattern.test(field)) return fail(`context.${key} is invalid`);
    context[key as keyof FeedbackContext] = field;
  }
  return { ok: true, value: context };
}

function parseText(value: unknown, maxTextLength: number): Result<string> {
  if (typeof value !== 'string') return fail('text must be a string');
  const text = value.trim();
  if (text.length === 0) return fail('text is empty');
  if (text.length > maxTextLength) return fail(`text is longer than ${maxTextLength} characters`);
  return { ok: true, value: text };
}

export function parsePayload(json: string, maxTextLength: number): Result<FeedbackPayload> {
  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch {
    return fail('payload is not valid json');
  }
  if (!isRecord(value)) return fail('payload is not a json object');
  const extra = unknownKey(value, ['type', 'text', 'screen', 'context']);
  if (extra !== undefined) return fail(`unexpected payload field ${extra}`);
  if (!TYPES.includes(value.type as FeedbackType)) return fail('type must be bug or idea');
  const text = parseText(value.text, maxTextLength);
  if (!text.ok) return text;
  const payload: FeedbackPayload = { type: value.type as FeedbackType, text: text.value };
  if (value.screen !== undefined) {
    if (typeof value.screen !== 'string' || !SCREEN.test(value.screen)) {
      return fail('screen is invalid');
    }
    payload.screen = value.screen;
  }
  if (value.context !== undefined) {
    const context = parseContext(value.context);
    if (!context.ok) return context;
    payload.context = context.value;
  }
  return { ok: true, value: payload };
}
