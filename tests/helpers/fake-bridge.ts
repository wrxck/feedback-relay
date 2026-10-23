import type { AppAttestBridge, AppAttestState, AppAttestStorage } from '../../src/client/index.js';
import { keyIdOf, makeAssertion, makeAttestation, newKey, type TestPki } from './fake-apple.js';

// stands in for DCAppAttestService: same inputs and outputs, test certificates instead of apple's
export function fakeBridge(pki: TestPki): AppAttestBridge & { counter: number } {
  const keys = new Map<string, ReturnType<typeof newKey>>();
  const bridge = {
    counter: 0,
    isSupported: () => Promise.resolve(true),
    generateKey() {
      const key = newKey();
      const keyId = keyIdOf(key.publicKey).text;
      keys.set(keyId, key);
      return Promise.resolve(keyId);
    },
    attestKey(keyId: string, hash: string) {
      const credential = keys.get(keyId)!;
      const clientDataHash = new Uint8Array(Buffer.from(hash, 'base64'));
      const object = makeAttestation({ pki, credential, clientDataHash });
      return Promise.resolve(Buffer.from(object).toString('base64'));
    },
    generateAssertion(keyId: string, hash: string) {
      bridge.counter += 1;
      const assertion = makeAssertion({
        privateKey: keys.get(keyId)!.privateKey,
        clientDataHash: new Uint8Array(Buffer.from(hash, 'base64')),
        counter: bridge.counter,
      });
      return Promise.resolve(Buffer.from(assertion).toString('base64'));
    },
  };
  return bridge;
}

export function memoryStorage(): AppAttestStorage & { state: AppAttestState | null } {
  const storage = {
    state: null as AppAttestState | null,
    load: () => Promise.resolve(storage.state),
    save(next: AppAttestState | null) {
      storage.state = next;
      return Promise.resolve();
    },
  };
  return storage;
}
