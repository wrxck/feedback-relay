// a minimal der reader: just enough to walk a certificate to its extensions, nothing more

export interface Tlv {
  tag: number;
  start: number;
  valueStart: number;
  end: number;
}

export class DerError extends Error {}

function readLength(bytes: Uint8Array, at: number): { length: number; next: number } {
  const first = bytes[at];
  if (first === undefined) throw new DerError('truncated length');
  if (first < 0x80) return { length: first, next: at + 1 };
  const count = first & 0x7f;
  // der forbids the indefinite form, and four length bytes already exceed any certificate
  if (count === 0 || count > 4) throw new DerError('unsupported length form');
  let length = 0;
  for (let i = 1; i <= count; i++) {
    const byte = bytes[at + i];
    if (byte === undefined) throw new DerError('truncated length');
    length = length * 256 + byte;
  }
  return { length, next: at + 1 + count };
}

export function readTlv(bytes: Uint8Array, at: number, limit = bytes.length): Tlv {
  const tag = bytes[at];
  if (tag === undefined || at >= limit) throw new DerError('truncated tag');
  // high tag numbers never appear in the structures this module reads
  if ((tag & 0x1f) === 0x1f) throw new DerError('unsupported tag');
  const { length, next } = readLength(bytes, at + 1);
  const end = next + length;
  if (end > limit) throw new DerError('value overruns its parent');
  return { tag, start: at, valueStart: next, end };
}

export function children(bytes: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.valueStart;
  while (at < parent.end) {
    const child = readTlv(bytes, at, parent.end);
    out.push(child);
    at = child.end;
  }
  return out;
}

export function valueOf(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.valueStart, tlv.end);
}

export function decodeOid(value: Uint8Array): string {
  const first = value[0];
  if (first === undefined) throw new DerError('empty oid');
  const parts = [Math.floor(first / 40), first % 40];
  let current = 0;
  for (const byte of value.subarray(1)) {
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(current);
      current = 0;
    }
  }
  return parts.join('.');
}

export function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (tlv?.tag !== tag) throw new DerError(`expected ${what}`);
  return tlv;
}
