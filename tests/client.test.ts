import { describe, expect, it, vi } from 'vitest';

import { type AttestProvider, createFeedbackClient } from '../src/client/index.js';

const challengeBody = { challenge: 'c'.repeat(43), expiresAt: 1 };
const reply = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });

function provider(overrides: Partial<AttestProvider> = {}) {
  return {
    name: 'test',
    prove: vi.fn().mockResolvedValue({ token: 't' }),
    accepted: vi.fn().mockResolvedValue(undefined),
    rejected: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function client(fetchMock: ReturnType<typeof vi.fn>, attest: AttestProvider = provider()) {
  return createFeedbackClient({
    endpoint: 'https://api.test/feedback/',
    attest,
    context: () => ({ appVersion: '1.0.0' }),
    fetch: fetchMock as unknown as typeof fetch,
  });
}

describe('feedback client', () => {
  it('fetches a challenge, proves the exact payload and submits it', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(reply(200, challengeBody));
    fetchMock.mockResolvedValueOnce(reply(201, { ok: true }));
    const prove = vi.fn().mockResolvedValue({ token: 't' });
    const attest = provider({ prove });
    const result = await client(fetchMock, attest).submit({
      type: 'bug',
      text: ' Hi ',
      screen: 'Home',
    });
    expect(result).toEqual({ ok: true });
    expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.test/feedback/challenge');
    const sent = JSON.parse((fetchMock.mock.calls[1]?.[1] as RequestInit).body as string) as {
      payload: string;
      challenge: string;
      proof: unknown;
    };
    expect(JSON.parse(sent.payload)).toEqual({
      type: 'bug',
      text: 'Hi',
      screen: 'Home',
      context: { appVersion: '1.0.0' },
    });
    expect(sent.challenge).toBe(challengeBody.challenge);
    expect(sent.proof).toEqual({ token: 't' });
    const { clientData, clientDataHash } = prove.mock.calls[0]?.[0] as {
      clientData: string;
      clientDataHash: Uint8Array;
    };
    expect(clientData.startsWith(`feedback-relay/v1|${challengeBody.challenge}|`)).toBe(true);
    expect(clientDataHash).toHaveLength(32);
    expect(attest.accepted).toHaveBeenCalled();
  });

  it('refuses empty text without a network call', async () => {
    const fetchMock = vi.fn();
    expect(await client(fetchMock).submit({ type: 'idea', text: '  ' })).toMatchObject({
      ok: false,
      error: 'bad_request',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('re-attests once when the server does not know the key', async () => {
    const unknown = { ok: false, error: 'unknown_key', message: 'send an attestation' };
    const fetchMock = vi.fn().mockResolvedValueOnce(reply(200, challengeBody));
    fetchMock.mockResolvedValueOnce(reply(401, unknown));
    fetchMock.mockResolvedValueOnce(reply(200, challengeBody));
    fetchMock.mockResolvedValueOnce(reply(201, { ok: true }));
    const attest = provider();
    expect(await client(fetchMock, attest).submit({ type: 'idea', text: 'x' })).toEqual({
      ok: true,
    });
    expect(attest.rejected).toHaveBeenCalledWith('unknown_key');
  });

  it('reports rate limiting with the retry delay', async () => {
    const limited = { ok: false, error: 'rate_limited', message: 'too many requests' };
    const fetchMock = vi.fn().mockResolvedValue(reply(429, limited, { 'retry-after': '30' }));
    expect(await client(fetchMock).submit({ type: 'idea', text: 'x' })).toEqual({
      ok: false,
      error: 'rate_limited',
      message: 'too many requests',
      retryAfterSeconds: 30,
    });
  });

  it('reports network, proof and non-json failures', async () => {
    const offline = vi.fn().mockRejectedValue(new Error('offline'));
    expect(await client(offline).submit({ type: 'bug', text: 'x' })).toMatchObject({
      error: 'network',
    });
    const ok = () => vi.fn().mockResolvedValueOnce(reply(200, challengeBody));
    const noProof = provider({ prove: vi.fn().mockRejectedValue(new Error('no secure enclave')) });
    expect(await client(ok(), noProof).submit({ type: 'bug', text: 'x' })).toMatchObject({
      error: 'attest_failed',
      message: 'no secure enclave',
    });
    const html = ok().mockResolvedValueOnce(reply(502, '<html>bad gateway</html>'));
    expect(await client(html).submit({ type: 'bug', text: 'x' })).toMatchObject({
      error: 'upstream_failed',
      message: 'server answered 502',
    });
    const odd = ok().mockResolvedValueOnce(reply(500, { ok: true }));
    expect(await client(odd).submit({ type: 'bug', text: 'x' })).toMatchObject({
      error: 'upstream_failed',
    });
  });

  it('works with a static context, no hooks and the global fetch', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(reply(200, challengeBody));
    spy.mockResolvedValueOnce(reply(201, { ok: true }));
    const result = await createFeedbackClient({
      endpoint: 'https://api.test/feedback',
      attest: { name: 'bare', prove: () => Promise.resolve({}) },
      context: { locale: 'en-GB' },
    }).submit({ type: 'idea', text: 'x' });
    expect(result).toEqual({ ok: true });
    spy.mockRestore();
  });

  it('rethrows a programming error rather than hiding it', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(reply(200, challengeBody));
    fetchMock.mockResolvedValueOnce(reply(201, { ok: true }));
    const attest = provider({ accepted: () => Promise.reject(new TypeError('bug')) });
    await expect(client(fetchMock, attest).submit({ type: 'bug', text: 'x' })).rejects.toThrow(
      TypeError,
    );
  });
});
