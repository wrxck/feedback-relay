import type { KeyObject, X509Certificate } from 'node:crypto';

import { fromBase64Url } from '../../shared/base64.js';
import {
  AAGUID_DEVELOPMENT,
  AAGUID_PRODUCTION,
  type AttestedAuthData,
  parseAttestedAuthData,
} from './auth-data.js';
import { sameBytes, sha256, utf8 } from './bytes.js';
import { bytesField, bytesListField, decodeMap, mapField } from './cbor.js';
import { readNonceExtension, verifyChain } from './certs.js';

export type AppAttestEnvironment = 'production' | 'development';

export interface AttestationRules {
  appId: string;
  environment: AppAttestEnvironment;
  rootPem: string;
  maxBytes: number;
}

export interface AttestedKey {
  publicKey: string;
  receipt: Uint8Array;
}

export class AttestationError extends Error {}

const FORMAT = 'apple-appattest';

// apple's uncompressed ec point: 0x04 | x | y, the input to the key id hash
function rawPoint(key: KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' });
  const x = jwk.x === undefined ? undefined : fromBase64Url(jwk.x);
  const y = jwk.y === undefined ? undefined : fromBase64Url(jwk.y);
  if (jwk.crv !== 'P-256' || x?.length !== 32 || y?.length !== 32) {
    throw new AttestationError('credential key is not a p-256 key');
  }
  return Uint8Array.of(0x04, ...x, ...y);
}

function checkAuthData(auth: AttestedAuthData, keyId: Uint8Array, rules: AttestationRules): void {
  if (!sameBytes(auth.rpIdHash, sha256(utf8(rules.appId)))) {
    throw new AttestationError('rp id hash does not match the app id');
  }
  if (auth.counter !== 0) throw new AttestationError('counter is not zero');
  const expected = rules.environment === 'production' ? AAGUID_PRODUCTION : AAGUID_DEVELOPMENT;
  if (!sameBytes(auth.aaguid, expected)) {
    throw new AttestationError(`aaguid is not the ${rules.environment} marker`);
  }
  if (!sameBytes(auth.credentialId, keyId)) {
    throw new AttestationError('credential id does not match the key id');
  }
}

function checkLeaf(
  leaf: X509Certificate,
  leafDer: Uint8Array,
  nonce: Uint8Array,
  keyId: Uint8Array,
) {
  if (!sameBytes(readNonceExtension(leafDer), nonce)) {
    throw new AttestationError('nonce does not match the challenge');
  }
  if (!sameBytes(sha256(rawPoint(leaf.publicKey)), keyId)) {
    throw new AttestationError('key id is not the hash of the credential key');
  }
}

// apple's "verify the attestation" steps 1 to 9, in order
export function verifyAttestation(
  attestation: Uint8Array,
  keyId: Uint8Array,
  clientDataHash: Uint8Array,
  rules: AttestationRules,
  now: Date,
): AttestedKey {
  const object = decodeMap(attestation, rules.maxBytes);
  if (object.fmt !== FORMAT) throw new AttestationError(`fmt is not ${FORMAT}`);
  const statement = mapField(object, 'attStmt');
  const x5c = bytesListField(statement, 'x5c');
  const authData = bytesField(object, 'authData');
  const leaf = verifyChain(x5c, rules.rootPem, now);
  checkLeaf(leaf, x5c[0] as Uint8Array, sha256(authData, clientDataHash), keyId);
  checkAuthData(parseAttestedAuthData(authData), keyId, rules);
  return {
    publicKey: leaf.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    receipt: bytesField(statement, 'receipt'),
  };
}
