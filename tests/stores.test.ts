import { describe, expect, it } from 'vitest';

import {
  CHALLENGE_PATTERN,
  createMemoryChallengeStore,
  issueChallenge,
} from '../src/server/challenge.js';
import { createMemoryRateLimiter } from '../src/server/rate-limit.js';

describe('memory challenge store', () => {
  it('issues a 256-bit url-safe challenge that can be taken once before expiry', async () => {
    const store = createMemoryChallengeStore();
    const { challenge, expiresAt } = await issueChallenge(store, 1000, 5000);
    expect(challenge).toMatch(CHALLENGE_PATTERN);
    expect(expiresAt).toBe(6000);
    expect(await store.take(challenge, 5500)).toBe(true);
    expect(await store.take(challenge, 5500)).toBe(false);
  });

  it('refuses an expired challenge', async () => {
    const store = createMemoryChallengeStore();
    const { challenge } = await issueChallenge(store, 1000, 0);
    expect(await store.take(challenge, 1000)).toBe(false);
  });

  it('drops the oldest challenge when full', async () => {
    const store = createMemoryChallengeStore({ maxEntries: 2 });
    await store.put('a', 10);
    await store.put('b', 10);
    await store.put('c', 10);
    expect(await store.take('a', 0)).toBe(false);
    expect(await store.take('c', 0)).toBe(true);
  });
});

describe('memory rate limiter', () => {
  it('allows max hits per window and reports the wait', async () => {
    const limiter = createMemoryRateLimiter({ max: 2, windowMs: 1000 });
    expect((await limiter.hit('k', 0)).allowed).toBe(true);
    expect((await limiter.hit('k', 100)).allowed).toBe(true);
    expect(await limiter.hit('k', 400)).toEqual({ allowed: false, retryAfterMs: 600 });
    expect((await limiter.hit('other', 400)).allowed).toBe(true);
    expect((await limiter.hit('k', 1000)).allowed).toBe(true);
  });

  it('evicts the oldest key when full', async () => {
    const limiter = createMemoryRateLimiter({ max: 1, windowMs: 1000, maxKeys: 1 });
    await limiter.hit('a', 0);
    await limiter.hit('b', 0);
    expect((await limiter.hit('a', 0)).allowed).toBe(true);
  });
});
