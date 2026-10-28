import { ThreatCategorySchema, type IndicatorType, type ThreatCategory } from '@bsp/policy-types';
import { hostnameMatchesDomain, normalizeIndicator, normalizedHash } from '@bsp/url-normalizer';
import type { RawIndicator } from './provider';

export interface ProcessedIndicator {
  readonly type: IndicatorType;
  readonly value: string;
  readonly hash: string;
  readonly hostname: string;
  readonly category: ThreatCategory;
  readonly confidence: number;
  readonly raw: string;
  readonly observedAt: string;
}

export interface PipelineReport {
  readonly fetched: number;
  readonly invalid: number;
  readonly duplicates: number;
  readonly suppressedBySafeList: number;
  readonly accepted: ProcessedIndicator[];
}

export interface PipelineOptions {
  readonly defaultCategory: ThreatCategory;
  readonly defaultConfidence: number;
  readonly safeDomains: readonly string[];
  readonly now?: Date;
}

const guessType = (value: string): IndicatorType =>
  /^[a-z][a-z0-9+.-]*:\/\//i.test(value.trim()) ? 'exact_url' : 'domain';
const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

/**
 * Stages 1-4 of the feed pipeline, pure and unit-tested:
 * validate -> normalize -> deduplicate -> score. (Store, update and expire
 * happen in the threats service inside one transaction.)
 */
export async function processFeed(
  raw: readonly RawIndicator[],
  opts: PipelineOptions,
): Promise<PipelineReport> {
  const now = (opts.now ?? new Date()).toISOString();
  const seen = new Map<string, ProcessedIndicator>();
  let invalid = 0;
  let duplicates = 0;
  let suppressed = 0;

  for (const r of raw) {
    if (typeof r?.value !== 'string' || r.value.length > 2048) {
      invalid++;
      continue;
    }
    const type = r.type ?? guessType(r.value);
    const n = normalizeIndicator(type, r.value);
    if (!n.ok) {
      invalid++;
      continue;
    }
    if (opts.safeDomains.some((d) => hostnameMatchesDomain(n.value.hostname, d))) {
      suppressed++;
      continue;
    }
    const category = ThreatCategorySchema.safeParse(r.category).success
      ? (r.category as ThreatCategory)
      : opts.defaultCategory;
    const confidence = clamp(
      typeof r.confidence === 'number' && Number.isFinite(r.confidence)
        ? r.confidence
        : opts.defaultConfidence,
    );
    const key = `${type}:${n.value.value}`;
    const prev = seen.get(key);
    if (prev) {
      duplicates++;
      // Keep the most confident observation of the same indicator.
      if (prev.confidence >= confidence) continue;
    }
    seen.set(key, {
      type,
      value: n.value.value,
      hash: await normalizedHash(type, n.value.value),
      hostname: n.value.hostname,
      category,
      confidence,
      raw: r.value,
      observedAt: r.observedAt ?? now,
    });
  }
  return {
    fetched: raw.length,
    invalid,
    duplicates,
    suppressedBySafeList: suppressed,
    accepted: [...seen.values()],
  };
}
