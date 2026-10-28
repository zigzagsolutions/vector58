import { PolicyPayloadSchema } from '@bsp/policy-types';
import { describe, expect, it } from 'vitest';
import {
  assignRuleIds,
  compilePolicy,
  computePolicyChecksum,
  decide,
  nextPolicyVersion,
  PRIORITY_BANDS,
  verifyPolicyChecksum,
  type CompileInput,
} from './index';
import { hostnameMatchesDomain } from '@bsp/url-normalizer';

const ORG = '11111111-1111-4111-8111-111111111111';
const NOW = '2026-10-28T12:00:00.000Z';

const base: CompileInput = {
  organizationId: ORG,
  policyVersion: 7,
  generatedAt: NOW,
  globalIndicators: [
    { indicatorType: 'domain', normalizedValue: 'global-bad.example', threatCategory: 'malware', confidence: 95, status: 'active', expiresAt: null },
    { indicatorType: 'domain', normalizedValue: 'shared.example', threatCategory: 'phishing', confidence: 90, status: 'active', expiresAt: null },
    { indicatorType: 'domain', normalizedValue: 'false-positive.example', threatCategory: 'phishing', confidence: 99, status: 'active', expiresAt: null },
    { indicatorType: 'domain', normalizedValue: 'low-confidence.example', threatCategory: 'fraud', confidence: 10, status: 'active', expiresAt: null },
    { indicatorType: 'domain', normalizedValue: 'expired.example', threatCategory: 'fraud', confidence: 99, status: 'active', expiresAt: '2026-01-01T00:00:00Z' },
    { indicatorType: 'domain', normalizedValue: 'revoked.example', threatCategory: 'fraud', confidence: 99, status: 'revoked', expiresAt: null },
  ],
  tenantRules: [
    { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'phase1-block-test.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
    { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'shared.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
    { ruleType: 'BLOCK_URL', normalizedValue: 'https://cdn.example/evil.exe', priority: 50, enabled: true, category: 'malicious-download', expiresAt: null },
    { ruleType: 'ALLOW_DOMAIN', normalizedValue: 'false-positive.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
    { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'disabled.example', priority: 100, enabled: false, category: 'custom', expiresAt: null },
    { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'NOT-NORMALIZED.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
  ],
};

describe('compilePolicy', () => {
  it('produces a schema-valid payload with a verifiable checksum', async () => {
    const { payload } = await compilePolicy(base);
    expect(PolicyPayloadSchema.safeParse(payload).success).toBe(true);
    expect(payload.checksum).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifyPolicyChecksum(payload)).toBe(true);
    expect(await verifyPolicyChecksum({ ...payload, policyVersion: 8 })).toBe(false);
    expect(await verifyPolicyChecksum({ ...payload, rules: payload.rules.slice(1) })).toBe(false);
  });

  it('is deterministic regardless of input order', async () => {
    const a = await compilePolicy(base);
    const b = await compilePolicy({
      ...base,
      globalIndicators: [...base.globalIndicators].reverse(),
      tenantRules: [...base.tenantRules].reverse(),
    });
    expect(JSON.stringify(b.payload)).toBe(JSON.stringify(a.payload));
  });

  it('keeps rule ids stable across versions and rule additions', async () => {
    const a = await compilePolicy(base);
    const b = await compilePolicy({
      ...base,
      policyVersion: 8,
      tenantRules: [
        ...base.tenantRules,
        { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'new.example', priority: 1, enabled: true, category: 'custom', expiresAt: null },
      ],
    });
    const idOf = (p: typeof a.payload, v: string) => p.rules.find((r) => r.value === v)?.id;
    expect(idOf(b.payload, 'phase1-block-test.example')).toBe(idOf(a.payload, 'phase1-block-test.example'));
    expect(b.payload.checksum).not.toBe(a.payload.checksum);
  });

  it('filters disabled, expired, revoked, low-confidence and unnormalised entries', async () => {
    const { payload, stats } = await compilePolicy(base);
    const values = payload.rules.map((r) => r.value);
    for (const v of ['disabled.example', 'expired.example', 'revoked.example', 'low-confidence.example', 'NOT-NORMALIZED.example']) {
      expect(values).not.toContain(v);
    }
    expect(stats.skippedInvalid).toBe(1);
    expect(stats.skippedExpiredOrDisabled).toBe(4);
  });

  it('excludes global intel when the policy opts out', async () => {
    const { payload } = await compilePolicy({ ...base, config: { includeGlobalThreats: false } });
    expect(payload.rules.every((r) => r.source === 'tenant')).toBe(true);
  });

  it('truncates by precedence when over maxRules', async () => {
    const { payload, stats } = await compilePolicy({ ...base, config: { maxRules: 2 } });
    expect(payload.rules).toHaveLength(2);
    expect(stats.truncated).toBeGreaterThan(0);
    expect(payload.rules.some((r) => r.action === 'allow')).toBe(true);
  });
});

describe('precedence', () => {
  const effective = async (host: string) => {
    const { payload } = await compilePolicy(base);
    const matching = payload.rules.filter((r) => r.type === 'domain' && hostnameMatchesDomain(host, r.value));
    return decide(matching);
  };

  it('1. org allow beats global block', async () => {
    const d = await effective('false-positive.example');
    expect(d.action).toBe('allow');
    expect(d.rule?.source).toBe('tenant');
  });
  it('2. org block applies', async () => {
    expect((await effective('www.phase1-block-test.example')).action).toBe('block');
  });
  it('2b. identical org block wins over global block (deduplicated)', async () => {
    const { payload, stats } = await compilePolicy(base);
    const shared = payload.rules.filter((r) => r.value === 'shared.example');
    expect(shared).toHaveLength(1);
    expect(shared[0]?.source).toBe('tenant');
    expect(stats.duplicates).toBe(1);
  });
  it('3. global block applies', async () => {
    const d = await effective('global-bad.example');
    expect(d.action).toBe('block');
    expect(d.rule?.source).toBe('global');
  });
  it('4. default allow', async () => {
    expect((await effective('example.org')).rule).toBeNull();
  });
  it('bands never overlap', async () => {
    const { payload } = await compilePolicy(base);
    for (const r of payload.rules) {
      if (r.action === 'allow') expect(r.priority).toBeGreaterThanOrEqual(PRIORITY_BANDS.ORG_ALLOW);
      if (r.source === 'tenant' && r.action === 'block') {
        expect(r.priority).toBeGreaterThanOrEqual(PRIORITY_BANDS.ORG_BLOCK);
        expect(r.priority).toBeLessThan(PRIORITY_BANDS.ORG_ALLOW);
      }
      if (r.source === 'global') expect(r.priority).toBeLessThan(PRIORITY_BANDS.ORG_BLOCK);
    }
  });
  it('allow wins ties like Chromium DNR', () => {
    expect(decide([{ action: 'block', priority: 5 }, { action: 'allow', priority: 5 }]).action).toBe('allow');
  });
});

describe('versioning and ids', () => {
  it('increments versions', () => {
    expect(nextPolicyVersion([])).toBe(1);
    expect(nextPolicyVersion([1, 2, 5])).toBe(6);
  });
  it('assigns unique ids under collisions', () => {
    const ids = assignRuleIds(Array.from({ length: 5000 }, (_, i) => `tenant|block|domain|d${i}.example`));
    expect(new Set(ids.values()).size).toBe(5000);
  });
  it('checksum covers all fields except checksum/signature', async () => {
    const { payload } = await compilePolicy(base);
    expect(await computePolicyChecksum({ ...payload, signature: 'sig' })).toBe(payload.checksum);
  });
});
