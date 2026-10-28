import type { ReportedSecurityEvent } from '@bsp/policy-types';
import { normalizeExactUrl, urlMatchesDomainRule, urlMatchesExactRule } from '@bsp/url-normalizer';
import type { AppliedPolicyMeta } from './state';

export interface ClientInfo {
  readonly clientId: string;
  readonly browser: 'chrome' | 'edge';
  readonly browserVersion: string | null;
  readonly extensionVersion: string;
}

/**
 * Turn a block-page report into a URL_BLOCKED event. The block page is web
 * accessible, so reports are validated against the applied policy: the rule
 * must exist, be a block rule, and match the reported URL. Unverifiable
 * reports are dropped.
 */
export function buildUrlBlockedEvent(
  report: { ruleId: number; url: string | null },
  policy: AppliedPolicyMeta | undefined,
  client: ClientInfo,
  eventId: string,
  now: Date,
): ReportedSecurityEvent | null {
  if (!policy) return null;
  const rule = policy.rules.find((r) => r.id === report.ruleId);
  if (!rule || rule.action !== 'block') return null;

  let url: string | null = null;
  if (report.url) {
    const n = normalizeExactUrl(report.url);
    if (n.ok) url = n.value;
  }
  if (rule.type === 'domain') {
    if (url && !urlMatchesDomainRule(url, rule.value)) return null;
  } else {
    if (url && !urlMatchesExactRule(url, rule.value)) return null;
    url = rule.value;
  }
  return {
    eventId,
    eventType: 'URL_BLOCKED',
    occurredAt: now.toISOString(),
    browserClientId: client.clientId,
    browser: client.browser,
    browserVersion: client.browserVersion,
    extensionVersion: client.extensionVersion,
    url: url ?? (rule.type === 'domain' ? `https://${rule.value}/` : rule.value),
    domain:
      rule.type === 'domain'
        ? url
          ? new URL(url).hostname
          : rule.value
        : new URL(rule.value).hostname,
    ruleId: rule.id,
    policyVersion: policy.policyVersion,
    threatCategory: rule.category,
    details: { urlCaptured: Boolean(url) },
  };
}

/** Suppress duplicate reports (reloads of the block page) within a short window. */
export class ReportDeduper {
  private readonly seen = new Map<string, number>();
  constructor(private readonly windowMs = 10_000) {}
  shouldReport(key: string, nowMs: number): boolean {
    for (const [k, t] of this.seen) if (nowMs - t > this.windowMs) this.seen.delete(k);
    if (this.seen.has(key)) return false;
    this.seen.set(key, nowMs);
    return true;
  }
}
