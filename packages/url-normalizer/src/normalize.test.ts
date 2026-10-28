import { describe, expect, it } from 'vitest';
import {
  extractHostname,
  hostnameMatchesDomain,
  normalizeAndDedupe,
  normalizeDomainRule,
  normalizeExactUrl,
  normalizedHash,
  normalizeHostname,
  normalizeIndicator,
  urlMatchesDomainRule,
  urlMatchesExactRule,
} from './index';

const value = <T>(r: { ok: true; value: T } | { ok: false }) => (r.ok ? r.value : undefined);
const code = (r: { ok: boolean; error?: { code: string } }) => (r.ok ? undefined : r.error?.code);

describe('normalizeHostname', () => {
  it('lowercases', () => expect(value(normalizeHostname('BaD-Domain.EXAMPLE'))).toBe('bad-domain.example'));
  it('strips trailing dots', () => expect(value(normalizeHostname('example.com..'))).toBe('example.com'));
  it('punycodes IDNs', () => {
    expect(value(normalizeHostname('bücher.example'))).toBe('xn--bcher-kva.example');
    expect(value(normalizeHostname('XN--BCHER-KVA.example'))).toBe('xn--bcher-kva.example');
  });
  it('handles full-width and mixed-script input through IDNA mapping', () => {
    expect(value(normalizeHostname('ＥＸＡＭＰＬＥ.com'))).toBe('example.com');
  });
  it('accepts IPv4', () => expect(value(normalizeHostname('10.0.0.1'))).toBe('10.0.0.1'));
  it('rejects IPv6', () => expect(code(normalizeHostname('[::1]'))).toBe('IP_V6_NOT_SUPPORTED'));
  it('rejects single label', () => expect(code(normalizeHostname('localhost'))).toBe('SINGLE_LABEL_HOSTNAME'));
  it('rejects empty', () => expect(code(normalizeHostname('   '))).toBe('EMPTY_INPUT'));
  it('rejects bad labels', () => {
    expect(code(normalizeHostname('-bad.example'))).toBe('INVALID_HOSTNAME');
    expect(code(normalizeHostname('bad_under.example'))).toBe('INVALID_HOSTNAME');
    expect(code(normalizeHostname(`${'a'.repeat(64)}.example`))).toBe('INVALID_HOSTNAME');
    expect(code(normalizeHostname('exa mple.com'))).toBe('INVALID_HOSTNAME');
  });
  it('rejects numeric TLD', () => expect(code(normalizeHostname('example.123'))).toBe('INVALID_HOSTNAME'));
});

describe('normalizeExactUrl', () => {
  it('drops default ports, fragments and credentials', () => {
    expect(value(normalizeExactUrl('HTTPS://user:pw@Example.COM:443/Path?q=1#frag'))).toBe(
      'https://example.com/Path?q=1',
    );
    expect(value(normalizeExactUrl('http://example.com:80'))).toBe('http://example.com/');
  });
  it('keeps non-default ports', () => {
    expect(value(normalizeExactUrl('https://example.com:8443/a'))).toBe('https://example.com:8443/a');
  });
  it('resolves dot segments and trailing host dots', () => {
    expect(value(normalizeExactUrl('https://example.com./a/../b/./c'))).toBe('https://example.com/b/c');
  });
  it('punycodes IDN hosts', () => {
    expect(value(normalizeExactUrl('https://bücher.example/x'))).toBe('https://xn--bcher-kva.example/x');
  });
  it('rejects unsupported schemes', () => {
    expect(code(normalizeExactUrl('ftp://example.com/'))).toBe('UNSUPPORTED_SCHEME');
    expect(code(normalizeExactUrl('javascript:alert(1)'))).toBe('UNSUPPORTED_SCHEME');
  });
  it('rejects missing scheme and malformed input', () => {
    expect(code(normalizeExactUrl('example.com/path'))).toBe('MISSING_SCHEME');
    expect(code(normalizeExactUrl('http://'))).toBe('MALFORMED');
    expect(code(normalizeExactUrl('http://exa mple.com/'))).toBe('MALFORMED');
  });
  it('rejects overly long URLs', () => {
    expect(code(normalizeExactUrl(`https://example.com/${'a'.repeat(3000)}`))).toBe('TOO_LONG');
  });
});

describe('domain rules', () => {
  it('accepts wildcards, URLs and paths', () => {
    expect(value(normalizeDomainRule('*.Bad.Example'))).toBe('bad.example');
    expect(value(normalizeDomainRule('https://login.bad.example:8443/x?y#z'))).toBe('login.bad.example');
    expect(value(normalizeDomainRule('bad.example/login'))).toBe('bad.example');
    expect(value(normalizeDomainRule('phase1-block-test.example'))).toBe('phase1-block-test.example');
  });
  it('extractHostname works for URLs and hosts', () => {
    expect(value(extractHostname('http://WWW.Example.com./'))).toBe('www.example.com');
    expect(value(extractHostname('www.example.com'))).toBe('www.example.com');
  });
});

describe('dedupe and hashing', () => {
  it('collapses equivalent inputs', () => {
    const r = normalizeAndDedupe([
      { kind: 'domain', value: 'Bad.Example' },
      { kind: 'domain', value: 'bad.example.' },
      { kind: 'domain', value: '*.bad.example' },
      { kind: 'exact_url', value: 'https://bad.example/a#x' },
      { kind: 'exact_url', value: 'https://BAD.example:443/a' },
      { kind: 'domain', value: 'not a domain' },
    ]);
    expect(r.unique.map((u) => u.value)).toEqual(['bad.example', 'https://bad.example/a']);
    expect(r.duplicates).toHaveLength(3);
    expect(r.invalid).toHaveLength(1);
  });
  it('hash is stable and kind-scoped', async () => {
    const a = await normalizedHash('domain', 'bad.example');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await normalizedHash('domain', 'bad.example')).toBe(a);
    expect(await normalizedHash('exact_url', 'bad.example')).not.toBe(a);
  });
  it('normalizeIndicator returns hostname', () => {
    expect(value(normalizeIndicator('exact_url', 'https://A.example/b'))?.hostname).toBe('a.example');
  });
});

describe('matching', () => {
  it('matches subdomains but not lookalikes', () => {
    expect(hostnameMatchesDomain('a.bad.example', 'bad.example')).toBe(true);
    expect(hostnameMatchesDomain('bad.example', 'bad.example')).toBe(true);
    expect(hostnameMatchesDomain('notbad.example', 'bad.example')).toBe(false);
    expect(urlMatchesDomainRule('https://X.Bad.Example./p', 'bad.example')).toBe(true);
    expect(urlMatchesExactRule('https://bad.example:443/a#f', 'https://bad.example/a')).toBe(true);
  });
});
