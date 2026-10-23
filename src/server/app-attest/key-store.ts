export interface StoredKey {
  // spki pem of the attested p-256 key
  publicKey: string;
  counter: number;
  // apple's attestation receipt, kept so a fraud metric check can be added later
  receipt: Uint8Array;
  createdAt: number;
}

export interface KeyStore {
  get(keyId: string): Promise<StoredKey | undefined>;
  // resolves false when the key id already exists, so a second attestation cannot replace a key
  create(keyId: string, key: StoredKey): Promise<boolean>;
  // compare and set: resolves true only when the stored counter is lower than next
  advanceCounter(keyId: string, next: number): Promise<boolean>;
}

export function createMemoryKeyStore(): KeyStore {
  const keys = new Map<string, StoredKey>();
  return {
    get: (keyId) => Promise.resolve(keys.get(keyId)),
    create(keyId, key) {
      if (keys.has(keyId)) return Promise.resolve(false);
      keys.set(keyId, { ...key });
      return Promise.resolve(true);
    },
    advanceCounter(keyId, next) {
      const key = keys.get(keyId);
      if (!key || key.counter >= next) return Promise.resolve(false);
      key.counter = next;
      return Promise.resolve(true);
    },
  };
}
