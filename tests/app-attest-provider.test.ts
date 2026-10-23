import { describe, expect, it, vi } from 'vitest';

import { createAppAttestProvider } from '../src/client/index.js';
import { makePki } from './helpers/fake-apple.js';
import { fakeBridge, memoryStorage } from './helpers/fake-bridge.js';

const hash = { clientData: 'x', clientDataHash: new Uint8Array(32) };

describe('app attest provider', () => {
  it('refuses on a device without app attest', async () => {
    const bridge = { ...fakeBridge(makePki()), isSupported: () => Promise.resolve(false) };
    const provider = createAppAttestProvider({ bridge, storage: memoryStorage() });
    await expect(provider.prove(hash)).rejects.toThrow(/not supported/);
  });

  it('drops the key when apple refuses to attest it', async () => {
    const bridge = fakeBridge(makePki());
    bridge.attestKey = vi.fn().mockRejectedValue(new Error('invalid key'));
    const storage = memoryStorage();
    const provider = createAppAttestProvider({ bridge, storage });
    await expect(provider.prove(hash)).rejects.toThrow(/invalid key/);
    expect(storage.state).toBeNull();
  });

  it('drops a key that no longer works on this device, so the next report starts over', async () => {
    const bridge = fakeBridge(makePki());
    bridge.generateAssertion = vi.fn().mockRejectedValue(new Error('invalid key'));
    const storage = memoryStorage();
    storage.state = { keyId: 'restored-from-backup', attested: true };
    const provider = createAppAttestProvider({ bridge, storage });
    await expect(provider.prove(hash)).rejects.toThrow(/invalid key/);
    expect(storage.state).toBeNull();
  });

  it('keeps state on other rejections and ignores accepted without a proof', async () => {
    const storage = memoryStorage();
    const provider = createAppAttestProvider({ bridge: fakeBridge(makePki()), storage });
    await provider.accepted?.();
    expect(storage.state).toBeNull();
    const proof = await provider.prove(hash);
    expect(proof).toHaveProperty('attestation');
    await provider.rejected?.('rate_limited');
    expect(storage.state?.attested).toBe(false);
  });
});
