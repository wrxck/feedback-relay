import { describe, expect, it } from 'vitest';

import { verifyAssertion } from '../src/server/app-attest/assertion.js';
import {
  createAppleAppAttestVerifier,
  createMemoryKeyStore,
} from '../src/server/app-attest/index.js';
import {
  BUNDLE_ID,
  keyIdOf,
  makeAssertion,
  makeAttestation,
  makePki,
  newKey,
  NOW,
  sha256,
  TEAM_ID,
} from './helpers/fake-apple.js';

const pki = makePki();
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const data = (text: string) => new TextEncoder().encode(text);

function setup() {
  const store = createMemoryKeyStore();
  const verifier = createAppleAppAttestVerifier({
    teamId: TEAM_ID,
    bundleId: BUNDLE_ID,
    keyStore: store,
    rootPem: pki.rootPem,
    now: () => NOW,
  });
  const credential = newKey();
  const keyId = keyIdOf(credential.publicKey).text;
  return { store, verifier, credential, keyId };
}

type Setup = ReturnType<typeof setup>;

function firstProof(s: Setup, clientData: Uint8Array, counter = 1) {
  const attestation = makeAttestation({
    pki,
    credential: s.credential,
    clientDataHash: sha256(clientData),
  });
  const assertion = makeAssertion({ privateKey: s.credential.privateKey, clientData, counter });
  return { keyId: s.keyId, attestation: b64(attestation), assertion: b64(assertion) };
}

function laterProof(s: Setup, clientData: Uint8Array, counter: number) {
  const assertion = makeAssertion({ privateKey: s.credential.privateKey, clientData, counter });
  return { keyId: s.keyId, assertion: b64(assertion) };
}

const input = (proof: Record<string, unknown>, clientData: Uint8Array) => ({
  proof,
  clientData,
  ip: '203.0.113.9',
});

describe('apple app attest verifier', () => {
  it('registers a key on first use and accepts later assertions', async () => {
    const s = setup();
    const first = data('one');
    expect(await s.verifier.verify(input(firstProof(s, first), first))).toEqual({
      ok: true,
      subject: s.keyId,
    });
    const second = data('two');
    expect((await s.verifier.verify(input(laterProof(s, second, 2), second))).ok).toBe(true);
    expect((await s.store.get(s.keyId))?.counter).toBe(2);
  });

  it('asks for an attestation when the key is unknown', async () => {
    const s = setup();
    const result = await s.verifier.verify(input(laterProof(s, data('x'), 1), data('x')));
    expect(result).toMatchObject({ ok: false, code: 'unknown_key' });
  });

  it('rejects a replayed assertion', async () => {
    const s = setup();
    const first = data('one');
    const proof = firstProof(s, first);
    expect((await s.verifier.verify(input(proof, first))).ok).toBe(true);
    const again = await s.verifier.verify(
      input({ keyId: s.keyId, assertion: proof.assertion }, first),
    );
    expect(again.ok).toBe(false);
    expect(!again.ok && again.reason).toMatch(/counter/);
  });

  it('rejects a counter that does not increase', async () => {
    const s = setup();
    const first = data('one');
    await s.verifier.verify(input(firstProof(s, first, 5), first));
    const next = data('two');
    const result = await s.verifier.verify(input(laterProof(s, next, 5), next));
    expect(result).toMatchObject({ ok: false, code: 'unverified' });
  });

  it('rejects a tampered body', async () => {
    const s = setup();
    const signed = data('the real body');
    const result = await s.verifier.verify(input(firstProof(s, signed), data('a forged body')));
    expect(result.ok).toBe(false);
  });

  it('refuses a racing request that loses the counter compare and set', async () => {
    const s = setup();
    const first = data('one');
    await s.verifier.verify(input(firstProof(s, first), first));
    const a = data('a');
    const b = data('b');
    const results = await Promise.all([
      s.verifier.verify(input(laterProof(s, a, 3), a)),
      s.verifier.verify(input(laterProof(s, b, 3), b)),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('ignores a second attestation for a registered key', async () => {
    const s = setup();
    const first = data('one');
    await s.verifier.verify(input(firstProof(s, first), first));
    const before = await s.store.get(s.keyId);
    const next = data('two');
    expect((await s.verifier.verify(input(firstProof(s, next, 2), next))).ok).toBe(true);
    expect((await s.store.get(s.keyId))?.publicKey).toBe(before?.publicKey);
  });

  it.each([
    [{}, /keyId/],
    [{ keyId: 'short', assertion: 'AA==' }, /keyId/],
    [{ keyId: 'A'.repeat(43) + '=' }, /assertion is missing/],
    [{ keyId: 'A'.repeat(43) + '=', assertion: '***' }, /assertion is not base64/],
    [{ keyId: 'A'.repeat(43) + '=', assertion: 'AA==', attestation: 3 }, /attestation is not text/],
    [{ keyId: 'A'.repeat(43) + '=', assertion: 'AA==', attestation: '%' }, /not base64/],
    [{ keyId: 'A'.repeat(43) + '=', assertion: 'AA==', extra: 1 }, /unexpected proof field/],
  ])('rejects a malformed proof %#', async (proof, reason) => {
    const s = setup();
    const result = await s.verifier.verify(input(proof, data('x')));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(reason);
  });

  it('uses apple production defaults', () => {
    const verifier = createAppleAppAttestVerifier({ teamId: TEAM_ID, bundleId: BUNDLE_ID });
    expect(verifier.name).toBe('apple-app-attest');
  });
});

describe('verifyAssertion', () => {
  const key = newKey();
  const pem = key.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const clientData = data('payload');
  const rules = { appId: `${TEAM_ID}.${BUNDLE_ID}`, maxBytes: 1024 };

  it('returns the new counter for a valid assertion', () => {
    const assertion = makeAssertion({ privateKey: key.privateKey, clientData, counter: 7 });
    expect(verifyAssertion(assertion, clientData, pem, 6, rules)).toBe(7);
  });

  it('rejects a signature from another key', () => {
    const assertion = makeAssertion({ privateKey: newKey().privateKey, clientData, counter: 7 });
    expect(() => verifyAssertion(assertion, clientData, pem, 0, rules)).toThrow(/signature/);
  });

  it('rejects a wrong rp id', () => {
    const assertion = makeAssertion({
      privateKey: key.privateKey,
      clientData,
      counter: 7,
      appId: 'OTHER.app',
    });
    expect(() => verifyAssertion(assertion, clientData, pem, 0, rules)).toThrow(/rp id/);
  });

  it('rejects a signature that is not der', async () => {
    const { encode } = await import('cborg');
    const bad = encode({ signature: Uint8Array.of(1, 2), authenticatorData: new Uint8Array(37) });
    expect(() => verifyAssertion(bad, clientData, pem, 0, rules)).toThrow(/signature/);
  });
});
