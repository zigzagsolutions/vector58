import { err, ok, sha256Hex, type Result } from '@bsp/shared';
import { MAX_URL_LENGTH, normalizeHostname } from './hostname';
import type { IndicatorKind, NormalizationError, NormalizedIndicator } from './types';

const SUPPORTED_SCHEMES = new Set(['http:', 'https:']);
const HAS_SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i;

export interface ParsedUrl {
  readonly scheme: 'http' | 'https';
  readonly hostname: string;
  /** Explicit non-default port, or null. */
  readonly port: number | null;
  readonly pathname: string;
  readonly search: string;
}

/**
 * Parse an absolute http(s) URL with the WHATWG parser and apply our
 * canonicalisation: lowercase scheme/host (parser), punycode IDNs (parser),
 * drop default ports (parser), strip trailing dots, strip credentials and
 * fragments.
 */
export function parseHttpUrl(input: string): Result<ParsedUrl, NormalizationError> {
  const raw = input.trim();
  if (!raw) return err({ code: 'EMPTY_INPUT', message: 'URL is empty', input });
  if (raw.length > MAX_URL_LENGTH) {
    return err({ code: 'TOO_LONG', message: `URL exceeds ${MAX_URL_LENGTH} characters`, input });
  }
  if (!HAS_SCHEME_RE.test(raw)) {
    return err({
      code: 'MISSING_SCHEME',
      message: 'URL must start with http:// or https://',
      input,
    });
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return err({ code: 'MALFORMED', message: `"${raw}" is not a valid URL`, input });
  }
  if (!SUPPORTED_SCHEMES.has(url.protocol)) {
    return err({
      code: 'UNSUPPORTED_SCHEME',
      message: `Scheme "${url.protocol}" is not supported; use http or https`,
      input,
    });
  }
  const host = normalizeHostname(url.hostname);
  if (!host.ok) return err({ ...host.error, input });

  return ok({
    scheme: url.protocol === 'https:' ? 'https' : 'http',
    hostname: host.value,
    port: url.port ? Number(url.port) : null,
    pathname: url.pathname || '/',
    search: url.search,
  });
}

export function formatParsedUrl(p: ParsedUrl): string {
  return `${p.scheme}://${p.hostname}${p.port === null ? '' : `:${p.port}`}${p.pathname}${p.search}`;
}

/** Canonical exact-URL form (no fragment, no credentials, no default port). */
export function normalizeExactUrl(input: string): Result<string, NormalizationError> {
  const parsed = parseHttpUrl(input);
  return parsed.ok ? ok(formatParsedUrl(parsed.value)) : parsed;
}

/** Extract the canonical hostname from a URL or bare host input. */
export function extractHostname(input: string): Result<string, NormalizationError> {
  const raw = input.trim();
  if (HAS_SCHEME_RE.test(raw) && raw.includes('//')) {
    const parsed = parseHttpUrl(raw);
    return parsed.ok ? ok(parsed.value.hostname) : parsed;
  }
  // Bare host, possibly followed by a path ("bad.example/login").
  const hostPart = raw.split(/[/?#]/, 1)[0] ?? '';
  return normalizeHostname(hostPart);
}

/**
 * Normalise a domain-rule input. Accepts "Example.COM", "example.com.",
 * "*.example.com", "https://example.com/path" and IDNs ("bücher.example").
 * Domain rules always cover subdomains, so a leading "*." is redundant.
 */
export function normalizeDomainRule(input: string): Result<string, NormalizationError> {
  const raw = input.trim().replace(/^\*\./, '').replace(/^\./, '');
  return extractHostname(raw);
}

export function normalizeIndicator(
  kind: IndicatorKind,
  input: string,
): Result<NormalizedIndicator, NormalizationError> {
  if (kind === 'domain') {
    const d = normalizeDomainRule(input);
    return d.ok ? ok({ kind, value: d.value, hostname: d.value }) : d;
  }
  const parsed = parseHttpUrl(input);
  if (!parsed.ok) return parsed;
  return ok({ kind, value: formatParsedUrl(parsed.value), hostname: parsed.value.hostname });
}

/** Stable hash used as a dedupe key: sha256("<kind>:<normalized value>"). */
export function normalizedHash(kind: IndicatorKind, normalizedValue: string): Promise<string> {
  return sha256Hex(`${kind}:${normalizedValue}`);
}

export interface DedupeResult {
  readonly unique: NormalizedIndicator[];
  readonly duplicates: { input: string; value: string }[];
  readonly invalid: NormalizationError[];
}

/** Normalise a batch, keeping the first occurrence of each canonical value. */
export function normalizeAndDedupe(
  items: readonly { kind: IndicatorKind; value: string }[],
): DedupeResult {
  const seen = new Set<string>();
  const unique: NormalizedIndicator[] = [];
  const duplicates: { input: string; value: string }[] = [];
  const invalid: NormalizationError[] = [];
  for (const item of items) {
    const n = normalizeIndicator(item.kind, item.value);
    if (!n.ok) {
      invalid.push(n.error);
      continue;
    }
    const key = `${n.value.kind}:${n.value.value}`;
    if (seen.has(key)) {
      duplicates.push({ input: item.value, value: n.value.value });
      continue;
    }
    seen.add(key);
    unique.push(n.value);
  }
  return { unique, duplicates, invalid };
}
