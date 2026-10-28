import { describe, expect, it } from 'vitest';
import {
  convertPolicyRules,
  diffRules,
  domainRegex,
  mainRuleId,
  policyRuleIdFromDnr,
  subRuleId,
} from '../src/background/rule-converter';
import { evaluate, makePolicy, ORIGIN } from './fakes';

describe('convertPolicyRules', () => {
  it('maps each policy rule to deterministic main/sub DNR ids', async () => {
    const p = await makePolicy(1);
    const { rules } = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN });
    for (const r of p.rules) {
      expect(rules.some((d) => d.id === mainRuleId(r.id))).toBe(true);
      if (r.action === 'block') expect(rules.some((d) => d.id === subRuleId(r.id))).toBe(true);
      expect(policyRuleIdFromDnr(mainRuleId(r.id))).toBe(r.id);
    }
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
    // Same input -> byte-identical output.
    expect(convertPolicyRules(p.rules, { extensionOrigin: ORIGIN })).toEqual({ rules, regexRuleCount: expect.any(Number) });
  });

  it('passes compiler priorities through unchanged', async () => {
    const p = await makePolicy(1);
    const { rules } = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN });
    for (const r of p.rules) expect(rules.find((d) => d.id === mainRuleId(r.id))?.priority).toBe(r.priority);
  });

  it('blocks a domain and its subdomains and redirects navigations to the block page with the URL', async () => {
    const p = await makePolicy(1);
    const { rules } = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN });
    const ruleId = p.rules.find((r) => r.value === 'phase1-block-test.example')!.id;
    for (const url of ['https://phase1-block-test.example/', 'http://www.phase1-block-test.example/a?b=c', 'https://phase1-block-test.example:8443/x#y']) {
      const res = evaluate(rules, url);
      expect(res.action).toBe('redirect');
      expect((res as { target: string }).target).toBe(`${ORIGIN}/blocked.html?r=${ruleId}#${url}`);
    }
    expect(evaluate(rules, 'https://phase1-block-test.example/img.png', 'image').action).toBe('block');
    expect(evaluate(rules, 'https://notphase1-block-test.example/').action).toBe('none');
    expect(evaluate(rules, 'https://phase1-block-test.example.evil.test/').action).toBe('none');
  });

  it('lets a tenant allow override a global block, including sub-resources', async () => {
    const p = await makePolicy(1);
    const { rules } = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN });
    expect(evaluate(rules, 'https://false-positive.example/').action).not.toBe('redirect');
    expect(evaluate(rules, 'https://false-positive.example/x.js', 'script').action).not.toBe('block');
  });

  it('allow outranks a lower band block at DNR level', () => {
    const rules = convertPolicyRules(
      [
        { id: 10, type: 'domain', value: 'example.org', action: 'block', category: 'malware', priority: 1095, source: 'global' },
        { id: 11, type: 'domain', value: 'safe.example.org', action: 'allow', category: 'custom', priority: 3100, source: 'tenant' },
      ],
      { extensionOrigin: ORIGIN },
    ).rules;
    expect(evaluate(rules, 'https://safe.example.org/').action).toBe('allow');
    expect(evaluate(rules, 'https://other.example.org/').action).toBe('redirect');
  });

  it('blocks exact URLs only', async () => {
    const p = await makePolicy(1);
    const { rules } = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN });
    expect(evaluate(rules, 'https://cdn.example/evil.exe').action).toBe('redirect');
    expect(evaluate(rules, 'https://cdn.example/evil.exe', 'other').action).toBe('block');
    expect(evaluate(rules, 'https://cdn.example/evil.exe2').action).toBe('none');
    expect(evaluate(rules, 'https://cdn.example/good.exe').action).toBe('none');
  });

  it('falls back to non-capturing redirects beyond the regex budget or for unsupported regexes', async () => {
    const p = await makePolicy(1);
    const limited = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN, regexBudget: 0 });
    expect(limited.regexRuleCount).toBe(0);
    const res = evaluate(limited.rules, 'https://phase1-block-test.example/');
    expect(res.action).toBe('redirect');
    expect((res as { target: string }).target).toMatch(/\/blocked\.html\?r=\d+$/);

    const bad = domainRegex('phase1-block-test.example');
    const unsupported = convertPolicyRules(p.rules, { extensionOrigin: ORIGIN, regexSupported: (r) => r !== bad });
    const main = unsupported.rules.find((r) => r.condition.requestDomains?.[0] === 'phase1-block-test.example' && r.action.type === 'redirect')!;
    expect(main.condition.regexFilter).toBeUndefined();
  });

  it('escapes regex metacharacters in values', () => {
    const { rules } = convertPolicyRules(
      [{ id: 5, type: 'exact_url', value: 'https://a.example/p?q=1+2&r=(x)', action: 'block', category: 'custom', priority: 2100, source: 'tenant' }],
      { extensionOrigin: ORIGIN },
    );
    expect(evaluate(rules, 'https://a.example/p?q=1+2&r=(x)').action).toBe('redirect');
    expect(evaluate(rules, 'https://a.example/p?q=1122&r=x').action).toBe('none');
  });
});

describe('diffRules', () => {
  it('computes minimal adds and removes', async () => {
    const v1 = convertPolicyRules((await makePolicy(1)).rules, { extensionOrigin: ORIGIN }).rules;
    expect(diffRules([], v1)).toMatchObject({ removeRuleIds: [], addRules: v1, unchanged: 0 });
    expect(diffRules(v1, v1)).toMatchObject({ removeRuleIds: [], addRules: [], unchanged: v1.length });

    const v2Policy = await makePolicy(2, {
      tenantRules: [{ ruleType: 'BLOCK_DOMAIN', normalizedValue: 'phase1-block-test.example', priority: 200, enabled: true, category: 'custom', expiresAt: null }],
    });
    const v2 = convertPolicyRules(v2Policy.rules, { extensionOrigin: ORIGIN }).rules;
    const d = diffRules(v1, v2);
    const v2Ids = new Set(v2.map((r) => r.id));
    // everything not in v2 is removed; changed priority -> remove + add same id
    for (const r of v1) if (!v2Ids.has(r.id)) expect(d.removeRuleIds).toContain(r.id);
    const changed = d.addRules.filter((r) => d.removeRuleIds.includes(r.id));
    expect(changed.length).toBeGreaterThan(0);
  });
});
