import { describe, expect, it } from 'vitest';
import { canonicalJson } from './canonical-json';
import { sha256Hex } from './hash';

describe('canonicalJson', () => {
  it('sorts keys and strips whitespace', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: 2 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":"é"}}',
    );
  });

  it('omits undefined members', () => {
    expect(canonicalJson({ a: undefined, b: 'q' })).toBe('{"b":"q"}');
  });

  it('rejects non-integer numbers', () => {
    expect(() => canonicalJson({ a: 1.5 })).toThrow(TypeError);
  });

  it('escapes strings like JSON.stringify', () => {
    expect(canonicalJson('a"b\\c\n\u0001')).toBe(JSON.stringify('a"b\\c\n\u0001'));
  });
});

describe('sha256Hex', () => {
  it('produces the well-known digest', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
