import { POLICY_SCHEMA_VERSION } from '@bsp/shared';
import type {
  CompiledRule,
  IndicatorType,
  PolicyPayload,
  PolicyRuleType,
  ThreatCategory,
} from '@bsp/policy-types';
import { normalizeIndicator } from '@bsp/url-normalizer';
import { computePolicyChecksum } from './checksum';
import { bandPriority, type PrecedenceBand } from './precedence';
import { assignRuleIds } from './rule-id';

export interface GlobalIndicatorInput {
  readonly indicatorType: IndicatorType;
  readonly normalizedValue: string;
  readonly threatCategory: ThreatCategory;
  readonly confidence: number;
  readonly status: 'active' | 'expired' | 'revoked';
  readonly expiresAt: string | null;
}

export interface TenantRuleInput {
  readonly ruleType: PolicyRuleType;
  readonly normalizedValue: string;
  readonly priority: number;
  readonly enabled: boolean;
  readonly category: ThreatCategory;
  readonly expiresAt: string | null;
}

export interface PolicyConfig {
  readonly includeGlobalThreats: boolean;
  /** Global indicators below this confidence are not enforced. */
  readonly minGlobalConfidence: number;
  /**
   * Upper bound on emitted rules. Each block rule becomes one "unsafe"
   * (redirect) DNR rule, and Chromium caps those at 5000 dynamic rules.
   */
  readonly maxRules: number;
}

export const DEFAULT_POLICY_CONFIG: PolicyConfig = {
  includeGlobalThreats: true,
  minGlobalConfidence: 75,
  maxRules: 4500,
};

export interface CompileInput {
  readonly organizationId: string;
  readonly policyVersion: number;
  readonly generatedAt: string;
  readonly globalIndicators: readonly GlobalIndicatorInput[];
  readonly tenantRules: readonly TenantRuleInput[];
  readonly config?: Partial<PolicyConfig>;
}

export interface CompileStats {
  readonly tenantAllow: number;
  readonly tenantBlock: number;
  readonly globalBlock: number;
  readonly skippedInvalid: number;
  readonly skippedExpiredOrDisabled: number;
  readonly suppressedByAllow: number;
  readonly duplicates: number;
  readonly truncated: number;
}

export interface CompileResult {
  readonly payload: PolicyPayload;
  readonly stats: CompileStats;
}

interface Candidate {
  readonly type: IndicatorType;
  readonly value: string;
  readonly action: 'block' | 'allow';
  readonly category: ThreatCategory;
  readonly priority: number;
  readonly source: 'tenant' | 'global';
  readonly band: PrecedenceBand;
}

const RULE_TYPE_MAP: Record<PolicyRuleType, { type: IndicatorType; action: 'block' | 'allow' }> = {
  BLOCK_DOMAIN: { type: 'domain', action: 'block' },
  BLOCK_URL: { type: 'exact_url', action: 'block' },
  ALLOW_DOMAIN: { type: 'domain', action: 'allow' },
  ALLOW_URL: { type: 'exact_url', action: 'allow' },
};

const isLive = (expiresAt: string | null, now: number) =>
  expiresAt === null || Date.parse(expiresAt) > now;

/**
 * Pure, deterministic compiler. Identical inputs (including generatedAt and
 * policyVersion) always produce byte-identical payloads and checksums;
 * input ordering does not matter.
 */
export async function compilePolicy(input: CompileInput): Promise<CompileResult> {
  const config = { ...DEFAULT_POLICY_CONFIG, ...input.config };
  const now = Date.parse(input.generatedAt);
  let skippedInvalid = 0;
  let skippedExpiredOrDisabled = 0;
  let duplicates = 0;

  const byKey = new Map<string, Candidate>();
  const add = (c: Candidate) => {
    const key = `${c.action}|${c.type}|${c.value}`;
    const existing = byKey.get(key);
    if (existing) {
      duplicates++;
      // Keep the higher-precedence copy (e.g. tenant block beats identical global block).
      if (c.priority <= existing.priority) return;
    }
    byKey.set(key, c);
  };

  for (const r of input.tenantRules) {
    if (!r.enabled || !isLive(r.expiresAt, now)) {
      skippedExpiredOrDisabled++;
      continue;
    }
    const map = RULE_TYPE_MAP[r.ruleType];
    // Defence in depth: values were normalised on write; re-normalise and drop anything invalid.
    const n = normalizeIndicator(map.type, r.normalizedValue);
    if (!n.ok || n.value.value !== r.normalizedValue) {
      skippedInvalid++;
      continue;
    }
    const band: PrecedenceBand = map.action === 'allow' ? 'ORG_ALLOW' : 'ORG_BLOCK';
    add({
      type: map.type,
      value: n.value.value,
      action: map.action,
      category: r.category,
      priority: bandPriority(band, r.priority),
      source: 'tenant',
      band,
    });
  }

  if (config.includeGlobalThreats) {
    for (const g of input.globalIndicators) {
      if (
        g.status !== 'active' ||
        !isLive(g.expiresAt, now) ||
        g.confidence < config.minGlobalConfidence
      ) {
        skippedExpiredOrDisabled++;
        continue;
      }
      const n = normalizeIndicator(g.indicatorType, g.normalizedValue);
      if (!n.ok || n.value.value !== g.normalizedValue) {
        skippedInvalid++;
        continue;
      }
      add({
        type: g.indicatorType,
        value: n.value.value,
        action: 'block',
        category: g.threatCategory,
        priority: bandPriority('GLOBAL_BLOCK', g.confidence),
        source: 'global',
        band: 'GLOBAL_BLOCK',
      });
    }
  }

  // A block identical to an allow exception can never fire; drop it.
  let suppressedByAllow = 0;
  for (const [key, c] of byKey) {
    if (c.action === 'block' && byKey.has(`allow|${c.type}|${c.value}`)) {
      byKey.delete(key);
      suppressedByAllow++;
    }
  }

  const sorted = [...byKey.values()].sort(
    (a, b) =>
      b.priority - a.priority ||
      a.type.localeCompare(b.type) ||
      a.value.localeCompare(b.value) ||
      a.action.localeCompare(b.action),
  );
  const kept = sorted.slice(0, config.maxRules);
  const truncated = sorted.length - kept.length;

  const identity = (c: Candidate) => `${c.source}|${c.action}|${c.type}|${c.value}`;
  const ids = assignRuleIds(kept.map(identity));

  const rules: CompiledRule[] = kept
    .map((c) => ({
      id: ids.get(identity(c)) as number,
      type: c.type,
      value: c.value,
      action: c.action,
      category: c.category,
      priority: c.priority,
      source: c.source,
    }))
    .sort((a, b) => a.id - b.id);

  const unsigned = {
    schemaVersion: POLICY_SCHEMA_VERSION as 1,
    policyVersion: input.policyVersion,
    organizationId: input.organizationId,
    generatedAt: input.generatedAt,
    rules,
  };
  const checksum = await computePolicyChecksum(unsigned);

  return {
    payload: { ...unsigned, checksum },
    stats: {
      tenantAllow: rules.filter((r) => r.source === 'tenant' && r.action === 'allow').length,
      tenantBlock: rules.filter((r) => r.source === 'tenant' && r.action === 'block').length,
      globalBlock: rules.filter((r) => r.source === 'global').length,
      skippedInvalid,
      skippedExpiredOrDisabled,
      suppressedByAllow,
      duplicates,
      truncated,
    },
  };
}
