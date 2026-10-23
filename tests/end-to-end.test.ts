import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createAppAttestProvider, createFeedbackClient } from '../src/client/index.js';
import {
  createAppleAppAttestVerifier,
  createFeedbackRelay,
  createMemoryKeyStore,
  expressHandlers,
} from '../src/server/index.js';
import { BUNDLE_ID, makePki, NOW, TEAM_ID } from './helpers/fake-apple.js';
import { fakeBridge, memoryStorage } from './helpers/fake-bridge.js';
import { recordingSink } from './helpers/relay-kit.js';

const pki = makePki();
let keyStore = createMemoryKeyStore();
const issues = recordingSink();
let server: Server;
let endpoint = '';

beforeAll(async () => {
  const relay = createFeedbackRelay({
    verifier: createAppleAppAttestVerifier({
      teamId: TEAM_ID,
      bundleId: BUNDLE_ID,
      rootPem: pki.rootPem,
      keyStore: {
        get: (k) => keyStore.get(k),
        create: (k, v) => keyStore.create(k, v),
        advanceCounter: (k, n) => keyStore.advanceCounter(k, n),
      },
      now: () => NOW,
    }),
    issues,
  });
  const handlers = expressHandlers(relay);
  server = createServer((req, res) => {
    const route = req.url === '/feedback/challenge' ? handlers.challenge : handlers.feedback;
    route(req, res).catch(() => res.end());
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/feedback`;
});

afterAll(
  () =>
    new Promise<void>((resolve) =>
      server.close(() => {
        resolve();
      }),
    ),
);

describe('client to server over http with app attest', () => {
  const bridge = fakeBridge(pki);
  const storage = memoryStorage();
  const client = () =>
    createFeedbackClient({
      endpoint,
      attest: createAppAttestProvider({ bridge, storage }),
      context: { appVersion: '1.2.0', os: 'iOS', osVersion: '18.1', locale: 'en-GB' },
    });

  it('attests on first use, then asserts only', async () => {
    const attestSpy = vi.spyOn(bridge, 'attestKey');
    expect(await client().submit({ type: 'bug', text: 'Crash, call 07700 900123' })).toEqual({
      ok: true,
    });
    expect(storage.state?.attested).toBe(true);
    expect(await client().submit({ type: 'idea', text: 'Dark mode', screen: 'Settings' })).toEqual({
      ok: true,
    });
    expect(attestSpy).toHaveBeenCalledTimes(1);
    expect(issues.drafts.map((d) => d.title)).toEqual([
      '[Bug] Crash, call [redacted]',
      '[Idea] Dark mode',
    ]);
  });

  it('recovers with a new key when the server forgets the old one', async () => {
    const before = storage.state?.keyId;
    keyStore = createMemoryKeyStore();
    expect(await client().submit({ type: 'bug', text: 'After a server reset' })).toEqual({
      ok: true,
    });
    expect(storage.state?.keyId).not.toBe(before);
    expect(storage.state?.attested).toBe(true);
  });
});
