import type { IndicatorType, ThreatCategory } from '@bsp/policy-types';

/** Raw indicator as delivered by a feed, before validation/normalisation. */
export interface RawIndicator {
  readonly value: string;
  readonly type?: IndicatorType;
  readonly category?: string;
  readonly confidence?: number;
  readonly observedAt?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface FeedFetchContext {
  readonly lastSync: Date | null;
  readonly config: Record<string, unknown>;
  readonly signal?: AbortSignal;
  /** Injected for testability; defaults to global fetch. */
  readonly fetch?: typeof fetch;
}

/**
 * Threat feed provider contract (IThreatFeedProvider). Providers only fetch
 * and map; validation, normalisation, dedupe, scoring, storage and expiry are
 * shared pipeline stages so every feed is held to the same rules.
 * Credentials must come from server env/vault, never threat_sources.config.
 */
export interface ThreatFeedProvider {
  readonly sourceType:
    'sample' | 'urlhaus' | 'openphish' | 'phishtank' | 'commercial' | 'internal' | 'manual';
  readonly defaultCategory: ThreatCategory;
  fetch(ctx: FeedFetchContext): Promise<RawIndicator[]>;
}

export class FeedNotConfiguredError extends Error {
  constructor(source: string) {
    super(`Threat feed "${source}" is not configured in this deployment`);
    this.name = 'FeedNotConfiguredError';
  }
}
