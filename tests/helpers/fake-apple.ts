import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
  sign,
  X509Certificate,
} from 'node:crypto';

import { encode } from 'cborg';

import {
  bitString,
  bool,
  explicit,
  generalizedTime,
  integer,
  octets,
  oid,
  seq,
  set,
  utf8String,
} from './der-writer.js';

export const TEAM_ID = 'ABCDE12345';
export const BUNDLE_ID = 'app.example.feedback';
export const APP_ID = `${TEAM_ID}.${BUNDLE_ID}`;

const DAY = 24 * 60 * 60 * 1000;
export const NOW = new Date('2026-06-01T12:00:00Z');

export const sha256 = (...parts: Uint8Array[]) => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
};

const utf8 = (text: string) => new Uint8Array(Buffer.from(text, 'utf8'));

export function newKey(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

const name = (cn: string) => seq(set(seq(oid('2.5.4.3'), utf8String(cn))));
const ecdsaSha256 = seq(oid('1.2.840.10045.4.3.2'));

interface CertSpec {
  subject: string;
  issuer: string;
  publicKey: KeyObject;
  signer: KeyObject;
  ca: boolean;
  extensions?: Uint8Array[];
  notBefore?: Date;
  notAfter?: Date;
}

export function makeCert(spec: CertSpec): Uint8Array {
  const spki = new Uint8Array(spec.publicKey.export({ type: 'spki', format: 'der' }));
  const extensions = [...(spec.extensions ?? [])];
  if (spec.ca) extensions.push(seq(oid('2.5.29.19'), bool(true), octets(seq(bool(true)))));
  const tbs = seq(
    explicit(0, integer(2)),
    integer(Math.floor(Math.random() * 1e9) + 1),
    ecdsaSha256,
    name(spec.issuer),
    seq(
      generalizedTime(spec.notBefore ?? new Date(NOW.getTime() - DAY)),
      generalizedTime(spec.notAfter ?? new Date(NOW.getTime() + DAY)),
    ),
    name(spec.subject),
    spki,
    ...(extensions.length > 0 ? [explicit(3, seq(...extensions))] : []),
  );
  const signature = new Uint8Array(sign('sha256', tbs, spec.signer));
  return seq(tbs, ecdsaSha256, bitString(signature));
}

export function nonceExtension(nonce: Uint8Array): Uint8Array {
  return seq(oid('1.2.840.113635.100.8.2'), octets(seq(explicit(1, octets(nonce)))));
}

export interface TestPki {
  rootPem: string;
  rootKey: KeyObject;
  intermediateDer: Uint8Array;
  intermediateKey: KeyObject;
}

export function makePki(): TestPki {
  const root = newKey();
  const intermediate = newKey();
  const rootDer = makeCert({
    subject: 'Test Root',
    issuer: 'Test Root',
    publicKey: root.publicKey,
    signer: root.privateKey,
    ca: true,
  });
  const intermediateDer = makeCert({
    subject: 'Test Intermediate',
    issuer: 'Test Root',
    publicKey: intermediate.publicKey,
    signer: root.privateKey,
    ca: true,
  });
  return {
    rootPem: new X509Certificate(rootDer).toString(),
    rootKey: root.privateKey,
    intermediateDer,
    intermediateKey: intermediate.privateKey,
  };
}

export function rawPoint(publicKey: KeyObject): Uint8Array {
  const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
  return spki.subarray(spki.length - 65);
}

export function aaguid(marker: string): Uint8Array {
  const out = new Uint8Array(16);
  out.set(utf8(marker));
  return out;
}

function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

export interface AttestationSpec {
  pki: TestPki;
  credential: { privateKey: KeyObject; publicKey: KeyObject };
  clientDataHash: Uint8Array;
  appId?: string;
  counter?: number;
  aaguid?: Uint8Array;
  credentialId?: Uint8Array;
  nonce?: Uint8Array;
  fmt?: string;
  leafSigner?: KeyObject;
  leafNotAfter?: Date;
  x5c?: Uint8Array[];
}

export function keyIdOf(publicKey: KeyObject): { bytes: Uint8Array; text: string } {
  const bytes = sha256(rawPoint(publicKey));
  return { bytes, text: Buffer.from(bytes).toString('base64') };
}

export function makeAttestation(spec: AttestationSpec): Uint8Array {
  const keyId = keyIdOf(spec.credential.publicKey).bytes;
  const credentialId = spec.credentialId ?? keyId;
  const authData = new Uint8Array(
    Buffer.concat([
      sha256(utf8(spec.appId ?? APP_ID)),
      Uint8Array.of(0x40),
      u32(spec.counter ?? 0),
      spec.aaguid ?? aaguid('appattest'),
      Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff),
      credentialId,
      encode(new Map<number, unknown>([[1, 2]])),
    ]),
  );
  const leaf = makeCert({
    subject: 'Test Credential',
    issuer: 'Test Intermediate',
    publicKey: spec.credential.publicKey,
    signer: spec.leafSigner ?? spec.pki.intermediateKey,
    ca: false,
    extensions: [nonceExtension(spec.nonce ?? sha256(authData, spec.clientDataHash))],
    ...(spec.leafNotAfter ? { notAfter: spec.leafNotAfter } : {}),
  });
  return encode({
    fmt: spec.fmt ?? 'apple-appattest',
    attStmt: { x5c: spec.x5c ?? [leaf, spec.pki.intermediateDer], receipt: utf8('receipt') },
    authData,
  });
}

export interface AssertionSpec {
  privateKey: KeyObject;
  clientData: Uint8Array;
  counter: number;
  appId?: string;
}

export function makeAssertion(spec: AssertionSpec): Uint8Array {
  const authenticatorData = new Uint8Array(
    Buffer.concat([sha256(utf8(spec.appId ?? APP_ID)), Uint8Array.of(0), u32(spec.counter)]),
  );
  const nonce = sha256(authenticatorData, sha256(spec.clientData));
  const signature = new Uint8Array(sign('sha256', nonce, spec.privateKey));
  return encode({ signature, authenticatorData });
}
