import { toBase64 } from '../shared/base64.js';
import type { AttestProvider } from './index.js';

// the four calls a native bridge must expose; every value crosses the bridge as base64 text
export interface AppAttestBridge {
  isSupported(): Promise<boolean>;
  generateKey(): Promise<string>;
  attestKey(keyId: string, clientDataHash: string): Promise<string>;
  generateAssertion(keyId: string, clientDataHash: string): Promise<string>;
}

export interface AppAttestState {
  keyId: string;
  attested: boolean;
}

// keep the state on the device, ideally in the keychain, so a reinstall starts over cleanly
export interface AppAttestStorage {
  load(): Promise<AppAttestState | null>;
  save(state: AppAttestState | null): Promise<void>;
}

export function createAppAttestProvider(options: {
  bridge: AppAttestBridge;
  storage: AppAttestStorage;
}): AttestProvider {
  const { bridge, storage } = options;
  let pending: AppAttestState | null = null;

  async function currentState(): Promise<AppAttestState> {
    const stored = await storage.load();
    if (stored) return stored;
    const created = { keyId: await bridge.generateKey(), attested: false };
    await storage.save(created);
    return created;
  }

  return {
    name: 'apple-app-attest',
    async prove({ clientDataHash }) {
      if (!(await bridge.isSupported())) throw new Error('app attest is not supported here');
      const state = await currentState();
      const hash = toBase64(clientDataHash);
      const proof: Record<string, unknown> = { keyId: state.keyId };
      if (!state.attested) {
        try {
          proof.attestation = await bridge.attestKey(state.keyId, hash);
        } catch (error) {
          // apple may refuse a key it has already attested; a new key is the documented recovery
          await storage.save(null);
          throw error;
        }
      }
      try {
        proof.assertion = await bridge.generateAssertion(state.keyId, hash);
      } catch (error) {
        // a key restored from a backup is not in this device's secure enclave, so only a new key can recover
        await storage.save(null);
        throw error;
      }
      pending = state;
      return proof;
    },
    async accepted() {
      if (pending && !pending.attested) await storage.save({ ...pending, attested: true });
      pending = null;
    },
    async rejected(error) {
      if (error === 'unknown_key') await storage.save(null);
      pending = null;
    },
  };
}
