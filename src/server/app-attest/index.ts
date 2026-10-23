import { fromBase64 } from '../../shared/base64.js';
import type { Verifier, VerifyInput, VerifyResult } from '../verifier.js';
import { APPLE_APP_ATTESTATION_ROOT_CA } from './apple-root.js';
import { verifyAssertion } from './assertion.js';
import { type AppAttestEnvironment, verifyAttestation } from './attestation.js';
import { sha256 } from './bytes.js';
import { createMemoryKeyStore, type KeyStore } from './key-store.js';

export interface AppAttestOptions {
  teamId: string;
  bundleId: string;
  environment?: AppAttestEnvironment;
  keyStore?: KeyStore;
  // a test chain's root; production code leaves it unset so apple's pinned root applies
  rootPem?: string;
  now?: () => Date;
}

const MAX_ATTESTATION = 16 * 1024;
const MAX_ASSERTION = 1024;
const KEY_ID = /^[A-Za-z0-9+/]{43}=$/;

interface AppAttestProof {
  keyId: string;
  keyHash: Uint8Array;
  assertion: Uint8Array;
  attestation: Uint8Array | undefined;
}

function readProof(proof: Record<string, unknown>): AppAttestProof | string {
  const { keyId, assertion, attestation } = proof;
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) return 'keyId is not a base64 sha-256';
  if (typeof assertion !== 'string') return 'assertion is missing';
  const assertionBytes = fromBase64(assertion);
  if (!assertionBytes) return 'assertion is not base64';
  if (attestation !== undefined && typeof attestation !== 'string')
    return 'attestation is not text';
  const attestationBytes = attestation === undefined ? undefined : fromBase64(attestation);
  if (attestation !== undefined && !attestationBytes) return 'attestation is not base64';
  const extra = Object.keys(proof).filter(
    (k) => !['keyId', 'assertion', 'attestation'].includes(k),
  );
  if (extra.length > 0) return `unexpected proof field ${extra[0] ?? ''}`;
  const keyHash = fromBase64(keyId) as Uint8Array;
  return { keyId, keyHash, assertion: assertionBytes, attestation: attestationBytes };
}

function fail(reason: string, code: 'unverified' | 'unknown_key' = 'unverified'): VerifyResult {
  return { ok: false, code, reason };
}

export function createAppleAppAttestVerifier(options: AppAttestOptions): Verifier {
  const appId = `${options.teamId}.${options.bundleId}`;
  const store = options.keyStore ?? createMemoryKeyStore();
  const rootPem = options.rootPem ?? APPLE_APP_ATTESTATION_ROOT_CA;
  const environment = options.environment ?? 'production';
  const now = options.now ?? (() => new Date());

  async function register(proof: AppAttestProof, clientData: Uint8Array): Promise<void> {
    if (!proof.attestation || (await store.get(proof.keyId))) return;
    const rules = { appId, environment, rootPem, maxBytes: MAX_ATTESTATION };
    const key = verifyAttestation(
      proof.attestation,
      proof.keyHash,
      sha256(clientData),
      rules,
      now(),
    );
    await store.create(proof.keyId, { ...key, counter: 0, createdAt: now().getTime() });
  }

  async function verify(input: VerifyInput): Promise<VerifyResult> {
    const proof = readProof(input.proof);
    if (typeof proof === 'string') return fail(proof);
    try {
      await register(proof, input.clientData);
      const stored = await store.get(proof.keyId);
      if (!stored) return fail('key is not attested; send an attestation', 'unknown_key');
      const rules = { appId, maxBytes: MAX_ASSERTION };
      const counter = verifyAssertion(
        proof.assertion,
        input.clientData,
        stored.publicKey,
        stored.counter,
        rules,
      );
      if (!(await store.advanceCounter(proof.keyId, counter)))
        return fail('assertion was replayed');
      return { ok: true, subject: proof.keyId };
    } catch (error) {
      return fail((error as Error).message);
    }
  }

  return { name: 'apple-app-attest', verify };
}

export { APPLE_APP_ATTESTATION_ROOT_CA } from './apple-root.js';
export type { AppAttestEnvironment } from './attestation.js';
export { createMemoryKeyStore, type KeyStore, type StoredKey } from './key-store.js';
