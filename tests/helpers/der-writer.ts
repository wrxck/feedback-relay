// a tiny der writer used only to mint test certificates; production code only ever reads der

function length(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

export function tlv(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = Buffer.concat(content);
  return new Uint8Array(Buffer.concat([Buffer.from([tag, ...length(body.length)]), body]));
}

export const seq = (...items: Uint8Array[]) => tlv(0x30, ...items);
export const set = (...items: Uint8Array[]) => tlv(0x31, ...items);
export const octets = (bytes: Uint8Array) => tlv(0x04, bytes);
export const explicit = (n: number, ...items: Uint8Array[]) => tlv(0xa0 | n, ...items);
export const bool = (value: boolean) => tlv(0x01, Uint8Array.of(value ? 0xff : 0));
export const utf8String = (text: string) => tlv(0x0c, new Uint8Array(Buffer.from(text, 'utf8')));
export const bitString = (bytes: Uint8Array) => tlv(0x03, Uint8Array.of(0), bytes);

export function integer(n: number): Uint8Array {
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  if (bytes.length === 0 || (bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return tlv(0x02, Uint8Array.from(bytes));
}

export function oid(dotted: string): Uint8Array {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [a! * 40 + b!];
  for (const part of rest) {
    const chunk: number[] = [];
    let v = part;
    do {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i]! |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(out));
}

export function generalizedTime(date: Date): Uint8Array {
  const text = date
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace(/\.\d+Z$/, 'Z');
  return tlv(0x18, new Uint8Array(Buffer.from(text, 'ascii')));
}
