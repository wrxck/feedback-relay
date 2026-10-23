import { describe, expect, it } from 'vitest';

import { parseEnvelope, parsePayload } from '../src/server/schema.js';

const challenge = 'a'.repeat(43);

describe('parseEnvelope', () => {
  it('accepts a well formed envelope', () => {
    const result = parseEnvelope({ payload: '{}', challenge, proof: {} }, 100);
    expect(result.ok).toBe(true);
  });

  it.each([
    [null, /json object/],
    [[], /json object/],
    [{ payload: '{}', challenge, proof: {}, userId: 'u1' }, /unexpected field userId/],
    [{ payload: {}, challenge, proof: {} }, /json string/],
    [{ payload: 'x'.repeat(101), challenge, proof: {} }, /too long/],
    [{ payload: '{}', challenge: 'short', proof: {} }, /challenge/],
    [{ payload: '{}', challenge, proof: 'x' }, /proof/],
  ])('rejects %#', (value, reason) => {
    const result = parseEnvelope(value, 100);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(reason);
  });
});

describe('parsePayload', () => {
  const full = {
    type: 'bug',
    text: '  It crashes  ',
    screen: 'Settings/Profile',
    context: { appVersion: '1.2.0', build: '45', os: 'iOS', osVersion: '18.1', locale: 'en_GB' },
  };

  it('accepts a full payload and trims the text', () => {
    const result = parsePayload(JSON.stringify(full), 100);
    expect(result).toEqual({ ok: true, value: { ...full, text: 'It crashes' } });
  });

  it('accepts a minimal payload', () => {
    expect(parsePayload('{"type":"idea","text":"x"}', 100).ok).toBe(true);
  });

  it.each([
    ['not json', /valid json/],
    ['[]', /json object/],
    [JSON.stringify({ ...full, deviceId: 'abc' }), /unexpected payload field deviceId/],
    [JSON.stringify({ ...full, type: 'praise' }), /bug or idea/],
    [JSON.stringify({ ...full, text: 5 }), /text must be a string/],
    [JSON.stringify({ ...full, text: '   ' }), /empty/],
    [JSON.stringify({ ...full, text: 'x'.repeat(101) }), /longer than 100/],
    [JSON.stringify({ ...full, screen: 'a|b' }), /screen/],
    [JSON.stringify({ ...full, screen: 7 }), /screen/],
    [JSON.stringify({ ...full, context: [] }), /context must be an object/],
    [JSON.stringify({ ...full, context: { userId: 'u' } }), /unexpected context field userId/],
    [JSON.stringify({ ...full, context: { toString: 'x' } }), /unexpected context field/],
    [JSON.stringify({ ...full, context: { locale: 'not a locale!' } }), /context.locale/],
    [JSON.stringify({ ...full, context: { build: 45 } }), /context.build/],
  ])('rejects %#', (json, reason) => {
    const result = parsePayload(json, 100);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(reason);
  });
});
