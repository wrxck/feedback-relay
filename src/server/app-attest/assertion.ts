import { createPublicKey, verify } from 'node:crypto';

import { parseAuthData } from './auth-data.js';
import { sameBytes, sha256, utf8 } from './bytes.js';
import { bytesField, decodeMap } from './cbor.js';

export interface AssertionRules {
  appId: string;
  maxBytes: number;
}

export class AssertionError extends Error {}

// node throws on a malformed der signature; that is a failed check, not a server error
function signatureValid(nonce: Uint8Array, publicKeyPem: string, signature: Uint8Array): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return verify('sha256', nonce, { key, dsaEncoding: 'der' }, signature);
  } catch {
    return false;
  }
}

// apple's "verify the assertion" steps 1 to 5; the caller owns the challenge and stores the counter
export function verifyAssertion(
  assertion: Uint8Array,
  clientData: Uint8Array,
  publicKeyPem: string,
  storedCounter: number,
  rules: AssertionRules,
): number {
  const object = decodeMap(assertion, rules.maxBytes);
  const signature = bytesField(object, 'signature');
  const authenticatorData = bytesField(object, 'authenticatorData');
  const nonce = sha256(authenticatorData, sha256(clientData));
  if (!signatureValid(nonce, publicKeyPem, signature)) {
    throw new AssertionError('signature does not verify');
  }
  const auth = parseAuthData(authenticatorData);
  if (!sameBytes(auth.rpIdHash, sha256(utf8(rules.appId)))) {
    throw new AssertionError('rp id hash does not match the app id');
  }
  if (auth.counter <= storedCounter) throw new AssertionError('counter did not increase');
  return auth.counter;
}
