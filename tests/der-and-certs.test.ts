import { createHash, X509Certificate } from 'node:crypto';

import { encode } from 'cborg';
import { describe, expect, it } from 'vitest';

import { APPLE_APP_ATTESTATION_ROOT_CA } from '../src/server/app-attest/apple-root.js';
import {
  AAGUID_DEVELOPMENT,
  parseAttestedAuthData,
  parseAuthData,
} from '../src/server/app-attest/auth-data.js';
import { bytesField, bytesListField, decodeMap, mapField } from '../src/server/app-attest/cbor.js';
import { readNonceExtension, verifyChain } from '../src/server/app-attest/certs.js';
import { children, decodeOid, readTlv } from '../src/server/app-attest/der.js';
import { createMemoryKeyStore } from '../src/server/app-attest/key-store.js';
import { makeCert, makePki, newKey, nonceExtension, NOW } from './helpers/fake-apple.js';
import { octets, oid, seq, tlv } from './helpers/der-writer.js';

describe('apple root', () => {
  it('is the published apple app attestation root', () => {
    const der = new X509Certificate(APPLE_APP_ATTESTATION_ROOT_CA).raw;
    const fingerprint = createHash('sha256').update(der).digest('hex').toUpperCase();
    expect(fingerprint).toBe('1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932');
  });
});

describe('der reader', () => {
  it('reads long form lengths and children', () => {
    const long = tlv(0x04, new Uint8Array(300));
    const parsed = readTlv(long, 0);
    expect(parsed.end - parsed.valueStart).toBe(300);
    expect(children(seq(long, long), readTlv(seq(long, long), 0))).toHaveLength(2);
  });

  it('decodes an oid', () => {
    const encoded = oid('1.2.840.113635.100.8.2');
    expect(decodeOid(encoded.subarray(2))).toBe('1.2.840.113635.100.8.2');
    expect(() => decodeOid(new Uint8Array())).toThrow(/empty/);
  });

  it.each([
    ['empty input', new Uint8Array()],
    ['truncated short length', Uint8Array.of(0x30)],
    ['indefinite length', Uint8Array.of(0x30, 0x80)],
    ['five byte length', Uint8Array.of(0x30, 0x85, 1, 1, 1, 1, 1)],
    ['truncated long length', Uint8Array.of(0x30, 0x82, 1)],
    ['overrun', Uint8Array.of(0x30, 0x05, 1)],
    ['high tag number', Uint8Array.of(0x1f, 0x01, 0x00)],
  ])('rejects %s', (_name, bytes) => {
    expect(() => readTlv(bytes, 0)).toThrow();
  });
});

describe('certificate helpers', () => {
  const pki = makePki();
  const key = newKey();
  const leafWith = (extensions: Uint8Array[]) =>
    makeCert({
      subject: 'Leaf',
      issuer: 'Test Intermediate',
      publicKey: key.publicKey,
      signer: pki.intermediateKey,
      ca: false,
      extensions,
    });

  it('reads the nonce from the extension, skipping others', () => {
    const nonce = new Uint8Array(32).fill(7);
    const other = seq(oid('2.5.29.14'), octets(octets(Uint8Array.of(1))));
    expect(readNonceExtension(leafWith([other, nonceExtension(nonce)]))).toEqual(nonce);
  });

  it('rejects a leaf with no extensions or no nonce extension', () => {
    expect(() => readNonceExtension(leafWith([]))).toThrow(/no app attest nonce/);
    const other = seq(oid('2.5.29.14'), octets(octets(Uint8Array.of(1))));
    expect(() => readNonceExtension(leafWith([other]))).toThrow(/no app attest nonce/);
  });

  it('reports a malformed nonce extension and malformed der', () => {
    const bad = seq(oid('1.2.840.113635.100.8.2'), octets(seq(octets(Uint8Array.of(1)))));
    expect(() => readNonceExtension(leafWith([bad]))).toThrow(/malformed leaf/);
    expect(() => readNonceExtension(Uint8Array.of(0x30, 0x80))).toThrow(/malformed leaf/);
  });

  it('rejects a root that has expired at the given time', () => {
    const leaf = leafWith([]);
    const later = new Date(NOW.getTime() + 10 * 24 * 3600 * 1000);
    expect(() => verifyChain([leaf, pki.intermediateDer], pki.rootPem, later)).toThrow(/date/);
  });
});

describe('authenticator data', () => {
  it('parses the header and the attested credential', () => {
    const bytes = new Uint8Array(37 + 16 + 2 + 4);
    bytes[36] = 9;
    bytes.set(AAGUID_DEVELOPMENT, 37);
    bytes[54] = 4;
    expect(parseAuthData(bytes).counter).toBe(9);
    expect(parseAttestedAuthData(bytes).credentialId).toHaveLength(4);
  });

  it('rejects short data', () => {
    expect(() => parseAuthData(new Uint8Array(10))).toThrow(/short/);
    expect(() => parseAttestedAuthData(new Uint8Array(40))).toThrow(/no attested credential/);
    const truncated = new Uint8Array(37 + 16 + 2);
    truncated[54] = 32;
    expect(() => parseAttestedAuthData(truncated)).toThrow(/truncated/);
  });
});

describe('cbor helpers', () => {
  it('rejects non-maps and wrong field types', () => {
    expect(() => decodeMap(encode([1]), 100)).toThrow(/not a map/);
    const map = decodeMap(encode({ a: 1, b: [1], c: 'x' }), 100);
    expect(() => bytesField(map, 'a')).toThrow(/byte string/);
    expect(() => mapField(map, 'a')).toThrow(/not a map/);
    expect(() => bytesListField(map, 'b')).toThrow(/list of byte strings/);
    expect(() => bytesListField(map, 'c')).toThrow(/list of byte strings/);
  });
});

describe('memory key store', () => {
  it('creates once and only advances the counter forwards', async () => {
    const store = createMemoryKeyStore();
    const key = { publicKey: 'pem', counter: 0, receipt: new Uint8Array(), createdAt: 1 };
    expect(await store.create('k', key)).toBe(true);
    expect(await store.create('k', key)).toBe(false);
    expect(await store.advanceCounter('k', 1)).toBe(true);
    expect(await store.advanceCounter('k', 1)).toBe(false);
    expect(await store.advanceCounter('missing', 1)).toBe(false);
  });
});
