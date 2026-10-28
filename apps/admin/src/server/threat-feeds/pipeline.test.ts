import { describe, expect, it } from 'vitest';
import { processFeed } from './pipeline';
import { parseUrlList, sampleFeedProvider } from './providers';

describe('threat feed pipeline', () => {
  it('validates, normalizes, dedupes, scores and applies the safe list', async () => {
    const raw = await sampleFeedProvider.fetch({ lastSync: null, config: {} });
    const r = await processFeed(raw, {
      defaultCategory: 'phishing',
      defaultConfidence: 80,
      safeDomains: ['microsoft.com'],
    });
    expect(r.fetched).toBe(9);
    expect(r.invalid).toBe(2);
    expect(r.duplicates).toBe(1);
    expect(r.suppressedBySafeList).toBe(1);
    expect(r.accepted.map((a) => a.value)).toContain('sample-phish-login.example');
    const phish = r.accepted.find((a) => a.value === 'sample-phish-login.example');
    expect(phish?.confidence).toBe(92);
    expect(r.accepted.find((a) => a.type === 'exact_url')?.value).toBe(
      'https://sample-malware-cdn.example/payload.exe',
    );
  });

  it('parses newline URL lists', () => {
    expect(parseUrlList('# header\nhttp://a.example/x\n\nhttps://b.example/\n')).toHaveLength(2);
  });

  it('clamps confidence and falls back to default category', async () => {
    const r = await processFeed([{ value: 'x.example', confidence: 400, category: 'nonsense' }], {
      defaultCategory: 'malware',
      defaultConfidence: 50,
      safeDomains: [],
    });
    expect(r.accepted[0]).toMatchObject({ confidence: 100, category: 'malware' });
  });
});
