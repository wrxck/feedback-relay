import { randomBytes } from 'node:crypto';

import { toBase64Url } from '../shared/base64.js';

export interface ChallengeStore {
  put(challenge: string, expiresAt: number): Promise<void>;
  // single use: resolves true at most once per challenge, and only before it expires
  take(challenge: string, now: number): Promise<boolean>;
}

export interface MemoryChallengeOptions {
  // a bound on memory; the oldest challenges are dropped first when it is reached
  maxEntries?: number;
}

export function createMemoryChallengeStore(options: MemoryChallengeOptions = {}): ChallengeStore {
  const maxEntries = options.maxEntries ?? 10_000;
  const entries = new Map<string, number>();
  return {
    put(challenge, expiresAt) {
      if (entries.size >= maxEntries) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
      entries.set(challenge, expiresAt);
      return Promise.resolve();
    },
    take(challenge, now) {
      const expiresAt = entries.get(challenge);
      entries.delete(challenge);
      return Promise.resolve(expiresAt !== undefined && expiresAt > now);
    },
  };
}

export const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export async function issueChallenge(
  store: ChallengeStore,
  ttlMs: number,
  now: number,
): Promise<{ challenge: string; expiresAt: number }> {
  const challenge = toBase64Url(randomBytes(32));
  const expiresAt = now + ttlMs;
  await store.put(challenge, expiresAt);
  return { challenge, expiresAt };
}
