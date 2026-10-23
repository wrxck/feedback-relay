import { createHash, timingSafeEqual } from 'node:crypto';

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
