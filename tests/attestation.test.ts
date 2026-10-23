import { describe, expect, it } from 'vitest';

import { verifyAttestation } from '../src/server/app-attest/attestation.js';
import {
  aaguid,
  APP_ID,
  keyIdOf,
  makeAttestation,
  makeCert,
  makePki,
  newKey,
  NOW,
  sha256,
} from './helpers/fake-apple.js';

const pki = makePki();
const credential = newKey();
const keyId = keyIdOf(credential.publicKey).bytes;
const clientDataHash = sha256(new TextEncoder().encode('client data'));
const rules = {
  appId: APP_ID,
  environment: 'production' as const,
  rootPem: pki.rootPem,
  maxBytes: 16384,
};

function attest(overrides: Partial<Parameters<typeof makeAttestation>[0]> = {}) {
  return makeAttestation({ pki, credential, clientDataHash, ...overrides });
}

describe('verifyAttestation', () => {
  it('accepts a genuine attestation and returns the key and receipt', () => {
    const result = verifyAttestation(attest(), keyId, clientDataHash, rules, NOW);
    expect(result.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(new TextDecoder().decode(result.receipt)).toBe('receipt');
  });

  it('accepts the development aaguid only in development', () => {
    const object = attest({ aaguid: aaguid('appattestdevelop') });
    const dev = { ...rules, environment: 'development' as const };
    expect(() => verifyAttestation(object, keyId, clientDataHash, dev, NOW)).not.toThrow();
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/aaguid/);
  });

  it('rejects a chain that does not reach the pinned root', () => {
    const other = makePki();
    expect(() =>
      verifyAttestation(attest(), keyId, clientDataHash, { ...rules, rootPem: other.rootPem }, NOW),
    ).toThrow(/apple root/);
  });

  it('rejects the default apple root for a test chain', async () => {
    const { APPLE_APP_ATTESTATION_ROOT_CA } =
      await import('../src/server/app-attest/apple-root.js');
    const real = { ...rules, rootPem: APPLE_APP_ATTESTATION_ROOT_CA };
    expect(() => verifyAttestation(attest(), keyId, clientDataHash, real, NOW)).toThrow();
  });

  it('rejects a leaf the intermediate did not sign', () => {
    const object = attest({ leafSigner: newKey().privateKey });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/leaf/);
  });

  it('rejects an expired leaf', () => {
    const object = attest({ leafNotAfter: new Date(NOW.getTime() - 1000) });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(
      /out of date/,
    );
  });

  it('rejects an intermediate that is not a ca', () => {
    const notCa = makeCert({
      subject: 'Test Intermediate',
      issuer: 'Test Root',
      publicKey: newKey().publicKey,
      signer: pki.rootKey,
      ca: false,
    });
    const leaf = makeCert({
      subject: 'L',
      issuer: 'Test Intermediate',
      publicKey: credential.publicKey,
      signer: pki.intermediateKey,
      ca: false,
    });
    const object = attest({ x5c: [leaf, notCa] });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/authority/);
  });

  it('rejects an x5c that is not exactly two certificates', () => {
    const object = attest({ x5c: [pki.intermediateDer] });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/x5c/);
  });

  it('rejects a wrong nonce', () => {
    const object = attest({ nonce: sha256(new Uint8Array([1])) });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/nonce/);
  });

  it('rejects a different client data hash', () => {
    const other = sha256(new TextEncoder().encode('tampered'));
    expect(() => verifyAttestation(attest(), keyId, other, rules, NOW)).toThrow(/nonce/);
  });

  it('rejects a wrong rp id', () => {
    const object = attest({ appId: 'ZZZZZ99999.other.app' });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/rp id/);
  });

  it('rejects a non-zero counter', () => {
    const object = attest({ counter: 1 });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/counter/);
  });

  it('rejects a credential id that is not the key id', () => {
    const object = attest({ credentialId: sha256(new Uint8Array([9])) });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(
      /credential/,
    );
  });

  it('rejects a key id that is not the hash of the leaf key', () => {
    const otherId = keyIdOf(newKey().publicKey).bytes;
    expect(() => verifyAttestation(attest(), otherId, clientDataHash, rules, NOW)).toThrow(
      /key id/,
    );
  });

  it('rejects another attestation format', () => {
    const object = attest({ fmt: 'packed' });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/fmt/);
  });

  it('rejects garbage and oversized input', () => {
    expect(() =>
      verifyAttestation(Uint8Array.of(0xff), keyId, clientDataHash, rules, NOW),
    ).toThrow();
    const small = { ...rules, maxBytes: 10 };
    expect(() => verifyAttestation(attest(), keyId, clientDataHash, small, NOW)).toThrow(/large/);
  });

  it('rejects a p-384 credential key', async () => {
    const { generateKeyPairSync } = await import('node:crypto');
    const big = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const object = attest({ credential: big });
    expect(() => verifyAttestation(object, keyId, clientDataHash, rules, NOW)).toThrow(/p-256/);
  });
});
