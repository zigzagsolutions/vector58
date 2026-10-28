import { FeedNotConfiguredError, type FeedFetchContext, type RawIndicator, type ThreatFeedProvider } from './provider';

/** Deterministic sample feed for development and tests (includes duplicates and junk on purpose). */
export const sampleFeedProvider: ThreatFeedProvider = {
  sourceType: 'sample',
  defaultCategory: 'phishing',
  async fetch() {
    return [
      { value: 'sample-phish-login.example', category: 'phishing', confidence: 92 },
      { value: 'SAMPLE-PHISH-LOGIN.example.', category: 'phishing', confidence: 80 },
      { value: 'https://sample-malware-cdn.example/payload.exe', type: 'exact_url', category: 'malicious-download', confidence: 97 },
      { value: 'sample-c2-beacon.example', category: 'command-and-control', confidence: 88 },
      { value: 'sample-credential-harvest.example', category: 'credential-theft', confidence: 85 },
      { value: 'sample-fraud-shop.example', category: 'fraud', confidence: 70 },
      { value: 'microsoft.com', category: 'phishing', confidence: 99 }, // must be suppressed by the safe list
      { value: 'not a domain', category: 'malware' },
      { value: 'javascript:alert(1)', type: 'exact_url', category: 'malware' },
    ];
  },
};

/** Parse a newline-delimited URL list (OpenPhish / URLhaus text exports). Comments start with '#'. */
export function parseUrlList(text: string, max = 50_000): RawIndicator[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .slice(0, max)
    .map((value) => ({ value, type: 'exact_url' as const }));
}

async function fetchText(ctx: FeedFetchContext, url: string): Promise<string> {
  const f = ctx.fetch ?? fetch;
  const res = await f(url, { signal: ctx.signal, headers: { accept: 'text/plain' } });
  if (!res.ok) throw new Error(`Feed request failed with HTTP ${res.status}`);
  return res.text();
}

/** URLhaus (abuse.ch) recent URL list. Free, no credentials; disabled by default. */
export const urlhausProvider: ThreatFeedProvider = {
  sourceType: 'urlhaus',
  defaultCategory: 'malware',
  async fetch(ctx) {
    const url = typeof ctx.config.url === 'string' ? ctx.config.url : 'https://urlhaus.abuse.ch/downloads/text_recent/';
    return parseUrlList(await fetchText(ctx, url)).map((i) => ({ ...i, category: 'malware' }));
  },
};

/** OpenPhish community feed. */
export const openPhishProvider: ThreatFeedProvider = {
  sourceType: 'openphish',
  defaultCategory: 'phishing',
  async fetch(ctx) {
    const url = typeof ctx.config.url === 'string' ? ctx.config.url : 'https://openphish.com/feed.txt';
    return parseUrlList(await fetchText(ctx, url)).map((i) => ({ ...i, category: 'phishing' }));
  },
};

/** PhishTank requires an application key (PHISHTANK_APP_KEY). Phase 2. */
export const phishTankProvider: ThreatFeedProvider = {
  sourceType: 'phishtank',
  defaultCategory: 'phishing',
  async fetch() {
    throw new FeedNotConfiguredError('phishtank');
  },
};

/** Placeholder for licensed commercial intelligence (credentials via vault). */
export const commercialProvider: ThreatFeedProvider = {
  sourceType: 'commercial',
  defaultCategory: 'custom',
  async fetch() {
    throw new FeedNotConfiguredError('commercial');
  },
};

export const PROVIDERS: Record<string, ThreatFeedProvider> = {
  sample: sampleFeedProvider,
  urlhaus: urlhausProvider,
  openphish: openPhishProvider,
  phishtank: phishTankProvider,
  commercial: commercialProvider,
};
