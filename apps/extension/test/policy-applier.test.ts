import { computePolicyChecksum } from '@bsp/policy-engine';
import { beforeEach, describe, expect, it } from 'vitest';
import { applyPolicyUpdate } from '../src/background/policy-applier';
import { ExtensionState } from '../src/background/state';
import { evaluate, FakePlatform, makePolicy, OTHER_ORG, update } from './fakes';

let platform: FakePlatform;
let state: ExtensionState;
beforeEach(() => {
  platform = new FakePlatform();
  state = new ExtensionState(platform);
});

const blocked = (url = 'https://phase1-block-test.example/') =>
  evaluate(platform.rules.values(), url).action === 'redirect';

describe('applyPolicyUpdate', () => {
  it('applies a valid policy and records last-known-good metadata', async () => {
    const p = await makePolicy(1);
    const out = await applyPolicyUpdate(update(p), platform, state);
    expect(out.status).toMatchObject({
      status: 'applied',
      policyVersion: 1,
      ruleCount: p.rules.length,
    });
    expect(blocked()).toBe(true);
    expect(await state.getPolicy()).toMatchObject({
      policyVersion: 1,
      checksum: p.checksum,
      organizationId: p.organizationId,
    });
  });

  it('reports unchanged for the same version and checksum without touching DNR', async () => {
    const p = await makePolicy(1);
    await applyPolicyUpdate(update(p), platform, state);
    const calls = platform.updateCalls;
    const out = await applyPolicyUpdate(update(p), platform, state);
    expect(out.status.status).toBe('unchanged');
    expect(platform.updateCalls).toBe(calls);
  });

  it('rejects malformed messages and keeps existing rules', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    for (const bad of [
      null,
      { type: 'POLICY_UPDATE' },
      { type: 'POLICY_UPDATE', policyVersion: 2, payload: { schemaVersion: 99 } },
    ]) {
      const out = await applyPolicyUpdate(bad, platform, state);
      expect(out.status).toMatchObject({ status: 'failed', policyVersion: 1 });
      expect(blocked()).toBe(true);
    }
  });

  it('rejects a checksum mismatch (tampered payload) and keeps existing rules', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    const p2 = await makePolicy(2);
    const tampered = {
      ...p2,
      rules: p2.rules.filter((r) => r.value !== 'phase1-block-test.example'),
    };
    const out = await applyPolicyUpdate(update(tampered), platform, state);
    expect(out.status.status).toBe('failed');
    expect(out.error).toMatch(/checksum/i);
    expect(blocked()).toBe(true);
    expect((await state.getPolicy())?.policyVersion).toBe(1);
  });

  it('refuses rollbacks to older versions', async () => {
    await applyPolicyUpdate(update(await makePolicy(3)), platform, state);
    const out = await applyPolicyUpdate(update(await makePolicy(2)), platform, state);
    expect(out.status.status).toBe('failed');
    expect(out.error).toMatch(/rollback/i);
    expect((await state.getPolicy())?.policyVersion).toBe(3);
  });

  it('refuses a policy for a different organization', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    const foreign = await makePolicy(5, { organizationId: OTHER_ORG });
    const out = await applyPolicyUpdate(update(foreign), platform, state);
    expect(out.status.status).toBe('failed');
    expect((await state.getPolicy())?.organizationId).not.toBe(OTHER_ORG);
  });

  it('rejects mismatched envelope and payload versions', async () => {
    const p = await makePolicy(4);
    const out = await applyPolicyUpdate({ ...update(p), policyVersion: 9 }, platform, state);
    expect(out.status.status).toBe('failed');
  });

  it('removes rules dropped from a newer version and adds new ones', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    const v2 = await makePolicy(2, {
      tenantRules: [
        {
          ruleType: 'BLOCK_DOMAIN',
          normalizedValue: 'new-block.example',
          priority: 100,
          enabled: true,
          category: 'custom',
          expiresAt: null,
        },
      ],
    });
    const out = await applyPolicyUpdate(update(v2), platform, state);
    expect(out.status.status).toBe('applied');
    expect(blocked()).toBe(false);
    expect(blocked('https://new-block.example/')).toBe(true);
    // Global threat still enforced; the tenant allow was removed so the global FP block now applies.
    expect(blocked('https://global-malware-test.example/')).toBe(true);
    expect(blocked('https://false-positive.example/')).toBe(true);
  });

  it('keeps previous rules when the browser rejects the update', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    platform.failNextUpdate = 'Dynamic rule count exceeded';
    const out = await applyPolicyUpdate(update(await makePolicy(2)), platform, state);
    expect(out.status).toMatchObject({ status: 'failed', policyVersion: 2 });
    expect(out.error).toMatch(/exceeded/);
    expect(blocked()).toBe(true);
    expect((await state.getPolicy())?.policyVersion).toBe(1);
  });

  it('falls back to non-capturing redirects when the browser rejects a regex', async () => {
    const p = await makePolicy(1);
    const { domainRegex } = await import('../src/background/rule-converter');
    platform.unsupportedRegex.add(domainRegex('phase1-block-test.example'));
    const out = await applyPolicyUpdate(update(p), platform, state);
    expect(out.status.status).toBe('applied');
    const res = evaluate(platform.rules.values(), 'https://phase1-block-test.example/');
    expect(res).toMatchObject({ action: 'redirect' });
    expect((res as { target: string }).target).toMatch(/blocked\.html\?r=\d+$/);
  });

  it('accepts an empty policy (all rules removed) as an explicit decision', async () => {
    await applyPolicyUpdate(update(await makePolicy(1)), platform, state);
    const empty = await makePolicy(2, { tenantRules: [], globalIndicators: [] });
    expect(empty.rules).toHaveLength(0);
    const out = await applyPolicyUpdate(update(empty), platform, state);
    expect(out.status.status).toBe('applied');
    expect(platform.rules.size).toBe(0);
  });

  it('checksum helper sanity: recomputed checksum matches', async () => {
    const p = await makePolicy(1);
    const { checksum: _c, signature: _s, ...rest } = p;
    expect(await computePolicyChecksum(rest)).toBe(p.checksum);
  });
});
