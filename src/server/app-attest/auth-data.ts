export class AuthDataError extends Error {}

export interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  counter: number;
}

export interface AttestedAuthData extends AuthData {
  aaguid: Uint8Array;
  credentialId: Uint8Array;
}

const HEADER = 37;
const AAGUID = 16;

// rpIdHash(32) | flags(1) | counter(4, big endian)
export function parseAuthData(bytes: Uint8Array): AuthData {
  if (bytes.length < HEADER) throw new AuthDataError('authenticator data is too short');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    rpIdHash: bytes.subarray(0, 32),
    flags: view.getUint8(32),
    counter: view.getUint32(33),
  };
}

// followed by aaguid(16) | credentialId length(2) | credentialId | cose public key
export function parseAttestedAuthData(bytes: Uint8Array): AttestedAuthData {
  const base = parseAuthData(bytes);
  if (bytes.length < HEADER + AAGUID + 2) {
    throw new AuthDataError('authenticator data has no attested credential');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const idLength = view.getUint16(HEADER + AAGUID);
  const idStart = HEADER + AAGUID + 2;
  if (bytes.length < idStart + idLength) throw new AuthDataError('credential id is truncated');
  return {
    ...base,
    aaguid: bytes.subarray(HEADER, HEADER + AAGUID),
    credentialId: bytes.subarray(idStart, idStart + idLength),
  };
}

export const AAGUID_PRODUCTION = aaguidOf('appattest');
export const AAGUID_DEVELOPMENT = aaguidOf('appattestdevelop');

// apple pads the production marker with zero bytes to 16
function aaguidOf(marker: string): Uint8Array {
  const out = new Uint8Array(AAGUID);
  out.set(new TextEncoder().encode(marker));
  return out;
}
