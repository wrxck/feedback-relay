import { Readable } from 'node:stream';

import { describe, expect, it, vi } from 'vitest';

import { expressHandlers, type NodeLikeResponse } from '../src/server/express.js';
import { createFeedbackRelay, type FeedbackRelay } from '../src/server/relay.js';
import { clientDataOf, echoVerifier, recordingSink } from './helpers/relay-kit.js';

function fakeResponse() {
  const res = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    body: undefined as string | undefined,
    setHeader(name: string, value: string) {
      res.headers[name] = value;
    },
    end(body?: string) {
      res.body = body;
    },
  };
  return res satisfies NodeLikeResponse;
}

const payload = JSON.stringify({ type: 'idea', text: 'Widgets' });

async function envelopeFrom(handlers: ReturnType<typeof expressHandlers>) {
  const res = fakeResponse();
  await handlers.challenge({ method: 'POST', ip: '192.0.2.1' }, res);
  const { challenge } = JSON.parse(res.body ?? '') as { challenge: string };
  return { payload, challenge, proof: { token: clientDataOf(challenge, payload) } };
}

describe('express adapter', () => {
  const relay = createFeedbackRelay({ verifier: echoVerifier, issues: recordingSink() });
  const handlers = expressHandlers(relay);

  it('serves a challenge and accepts a parsed body', async () => {
    const res = fakeResponse();
    await handlers.feedback(
      { method: 'POST', body: await envelopeFrom(handlers), ip: '192.0.2.1' },
      res,
    );
    expect(res.statusCode).toBe(201);
    expect(res.headers['content-type']).toBe('application/json');
  });

  it('reads a raw stream when no body parser ran, using the socket address', async () => {
    const body = JSON.stringify(await envelopeFrom(handlers));
    const req = Object.assign(Readable.from([Buffer.from(body.slice(0, 10)), body.slice(10)]), {
      method: 'POST',
      socket: { remoteAddress: '192.0.2.2' },
    });
    const res = fakeResponse();
    await handlers.feedback(req, res);
    expect(res.statusCode).toBe(201);
  });

  it('answers 413 for an oversized stream', async () => {
    const small = expressHandlers(relay, { maxBodyBytes: 8 });
    const req = Object.assign(Readable.from([Buffer.alloc(16)]), { method: 'POST' });
    const res = fakeResponse();
    await small.feedback(req, res);
    expect(res.statusCode).toBe(413);
  });

  it('answers 400 when there is no body at all', async () => {
    const res = fakeResponse();
    await handlers.feedback({ method: 'POST' }, res);
    expect(res.statusCode).toBe(400);
  });

  it('passes unexpected errors to next, or answers 500 without it', async () => {
    const broken = {
      handleChallenge: () => Promise.reject(new Error('boom')),
      handleFeedback: () => Promise.reject(new Error('boom')),
    } satisfies FeedbackRelay;
    const brokenHandlers = expressHandlers(broken);
    const next = vi.fn();
    await brokenHandlers.challenge({ method: 'POST' }, fakeResponse(), next);
    expect(next).toHaveBeenCalledWith(expect.any(Error));
    const res = fakeResponse();
    await brokenHandlers.feedback({ method: 'POST', body: {} }, res);
    expect(res.statusCode).toBe(500);
  });

  it('rethrows a stream error to next', async () => {
    const req = Object.assign(
      new Readable({
        read() {
          this.destroy(new Error('socket reset'));
        },
      }),
      { method: 'POST' },
    );
    const next = vi.fn();
    await handlers.feedback(req, fakeResponse(), next);
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ message: 'socket reset' }));
  });
});
