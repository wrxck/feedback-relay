import { decode } from 'cborg';

export class CborError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// cborg rejects trailing bytes and undefined; a size cap keeps a hostile blob cheap to refuse
export function decodeMap(bytes: Uint8Array, maxBytes: number): Record<string, unknown> {
  if (bytes.length > maxBytes) throw new CborError('cbor object is too large');
  let value: unknown;
  try {
    value = decode(bytes, { rejectDuplicateMapKeys: true });
  } catch (error) {
    throw new CborError(`cbor decode failed: ${(error as Error).message}`);
  }
  if (!isRecord(value)) throw new CborError('cbor object is not a map');
  return value;
}

export function bytesField(map: Record<string, unknown>, key: string): Uint8Array {
  const value = map[key];
  if (!(value instanceof Uint8Array)) throw new CborError(`${key} is not a byte string`);
  return value;
}

export function mapField(map: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = map[key];
  if (!isRecord(value)) throw new CborError(`${key} is not a map`);
  return value;
}

export function bytesListField(map: Record<string, unknown>, key: string): Uint8Array[] {
  const value = map[key];
  if (!Array.isArray(value) || !value.every((item) => item instanceof Uint8Array)) {
    throw new CborError(`${key} is not a list of byte strings`);
  }
  return value;
}
