import { describe, expect, it } from 'vitest';

import { createFeedbackRelay, type FeedbackRelayOptions } from '../src/server/relay.js';
import { clientDataOf, echoVerifier, recordingSink } from './helpers/relay-kit.js';

const payload = JSON.stringify({ type: 'bug', text: 'Crash when saving' });

function setup(overrides: Partial<FeedbackRelayOptions> = {}) {
  const issues = recordingSink();
  const events: string[] = [];
  const relay = createFeedbackRelay({
    verifier: echoVerifier,
    issues,
    onEvent: (event) => events.push(event.kind === 'rejected' ? event.reason : event.kind),
    ...overrides,
  });
  async function challenge(ip = '198.51.100.1'): Promise<string> {
    const response = await relay.handleChallenge({ method: 'POST', ip });
    return (JSON.parse(response.body) as { challenge: string }).challenge;
  }
  async function send(body: unknown, ip = '198.51.100.1') {
    const response = await relay.handleFeedback({ method: 'POST', body, ip });
    return { ...response, json: JSON.parse(response.body) as Record<string, unknown> };
  }
  async function valid(text = payload, subject?: string) {
    const fresh = await challenge();
    const proof = { token: clientDataOf(fresh, text), ...(subject ? { subject } : {}) };
    return { payload: text, challenge: fresh, proof };
  }
  return { relay, issues, events, challenge, send, valid };
}

describe('feedback relay', () => {
  it('files an issue for a verified report', async () => {
    const t = setup();
    const response = await t.send(JSON.stringify(await t.valid()));
    expect(response.status).toBe(201);
    expect(response.json).toEqual({ ok: true });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(t.issues.drafts[0]?.title).toBe('[Bug] Crash when saving');
    expect(t.events).toEqual(['created']);
  });

  it('accepts bytes and pre-parsed bodies', async () => {
    const t = setup();
    const bytes = new TextEncoder().encode(JSON.stringify(await t.valid()));
    expect((await t.send(bytes)).status).toBe(201);
    expect((await t.send(await t.valid())).status).toBe(201);
  });

  it('rejects a reused challenge', async () => {
    const t = setup();
    const envelope = await t.valid();
    await t.send(envelope);
    const again = await t.send(envelope);
    expect(again.status).toBe(401);
    expect(again.json.error).toBe('bad_challenge');
  });

  it('rejects an expired challenge', async () => {
    let now = 0;
    const t = setup({ now: () => now, challengeTtlMs: 1000 });
    const envelope = await t.valid();
    now = 1001;
    expect((await t.send(envelope)).json.error).toBe('bad_challenge');
  });

  it('rejects a payload changed after signing, without leaking the reason', async () => {
    const t = setup();
    const envelope = await t.valid();
    const tampered = { ...envelope, payload: JSON.stringify({ type: 'bug', text: 'other' }) };
    const response = await t.send(tampered);
    expect(response.status).toBe(401);
    expect(response.json).toEqual({
      ok: false,
      error: 'unverified',
      message: 'app proof was not accepted',
    });
    expect(t.events).toEqual(['token mismatch']);
  });

  it.each([
    [undefined, 400, 'bad_request'],
    ['{', 400, 'bad_request'],
    [new Uint8Array([0xff, 0xfe]), 400, 'bad_request'],
    ['x'.repeat(70_000), 413, 'too_large'],
    [{ payload: 1 }, 400, 'bad_request'],
  ])('rejects malformed body %#', async (body, status, error) => {
    const t = setup();
    const response = await t.send(body);
    expect(response.status).toBe(status);
    expect(response.json.error).toBe(error);
  });

  it('rejects an invalid payload before spending the challenge', async () => {
    const t = setup();
    const envelope = await t.valid(JSON.stringify({ type: 'bug', text: '' }));
    expect((await t.send(envelope)).json.error).toBe('bad_request');
    const fixed = {
      ...envelope,
      payload,
      proof: { token: clientDataOf(envelope.challenge, payload) },
    };
    expect((await t.send(fixed)).status).toBe(201);
  });

  it('rejects other methods', async () => {
    const t = setup();
    expect((await t.relay.handleFeedback({ method: 'GET', body: '' })).status).toBe(405);
    expect((await t.relay.handleChallenge({ method: 'GET' })).status).toBe(405);
  });

  it('rate limits per ip on both routes with retry-after', async () => {
    const { createMemoryRateLimiter } = await import('../src/server/rate-limit.js');
    const t = setup({ ipLimiter: createMemoryRateLimiter({ max: 1, windowMs: 60_000 }) });
    await t.challenge('203.0.113.5');
    const limited = await t.relay.handleChallenge({ method: 'POST', ip: '203.0.113.5' });
    expect(limited.status).toBe(429);
    expect(limited.headers['retry-after']).toBe('60');
    const envelope = await t.valid();
    await t.send(envelope, '203.0.113.6');
    expect((await t.send(envelope, '203.0.113.6')).status).toBe(429);
  });

  it('rate limits per verified subject', async () => {
    const { createMemoryRateLimiter } = await import('../src/server/rate-limit.js');
    const t = setup({ subjectLimiter: createMemoryRateLimiter({ max: 1, windowMs: 60_000 }) });
    expect((await t.send(await t.valid(payload, 'device-a'))).status).toBe(201);
    expect((await t.send(await t.valid(payload, 'device-a'))).status).toBe(429);
    expect((await t.send(await t.valid(payload, 'device-b'))).status).toBe(201);
  });

  it('answers 502 when github fails', async () => {
    const t = setup({ issues: recordingSink(true) });
    const response = await t.send(await t.valid());
    expect(response.status).toBe(502);
    expect(response.json.error).toBe('upstream_failed');
  });

  it('passes extra labels and works without an event hook', async () => {
    const issues = recordingSink();
    const relay = createFeedbackRelay({ verifier: echoVerifier, issues, extraLabels: ['ios'] });
    const issued = JSON.parse((await relay.handleChallenge({})).body) as { challenge: string };
    const proof = { token: clientDataOf(issued.challenge, payload) };
    const response = await relay.handleFeedback({
      body: { payload, challenge: issued.challenge, proof },
    });
    expect(response.status).toBe(201);
    expect(issues.drafts[0]?.labels).toContain('ios');
  });

  it('rethrows unexpected errors', async () => {
    const t = setup({
      verifier: { name: 'broken', verify: () => Promise.reject(new TypeError('bug')) },
    });
    await expect(t.send(await t.valid())).rejects.toThrow(TypeError);
  });
});
