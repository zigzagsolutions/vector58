import { compilePolicy, type CompileInput } from '@bsp/policy-engine';
import type { PolicyPayload } from '@bsp/policy-types';
import type { DnrRule, ResourceType } from '../src/background/dnr-types';
import type { NativePort } from '../src/background/native-port';
import type { ExtensionPlatform } from '../src/background/platform';

export const ORG = '11111111-1111-4111-8111-111111111111';
export const OTHER_ORG = '22222222-2222-4222-8222-222222222222';
export const EXT_ID = 'ikgimjohebonbmlfdngiiebaadojbdmp';
export const ORIGIN = `chrome-extension://${EXT_ID}`;

export async function makePolicy(version: number, overrides: Partial<CompileInput> = {}): Promise<PolicyPayload> {
  const { payload } = await compilePolicy({
    organizationId: ORG,
    policyVersion: version,
    generatedAt: '2026-10-28T12:00:00.000Z',
    globalIndicators: [
      { indicatorType: 'domain', normalizedValue: 'global-malware-test.example', threatCategory: 'malware', confidence: 95, status: 'active', expiresAt: null },
      { indicatorType: 'domain', normalizedValue: 'false-positive.example', threatCategory: 'phishing', confidence: 99, status: 'active', expiresAt: null },
    ],
    tenantRules: [
      { ruleType: 'BLOCK_DOMAIN', normalizedValue: 'phase1-block-test.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
      { ruleType: 'BLOCK_URL', normalizedValue: 'https://cdn.example/evil.exe', priority: 50, enabled: true, category: 'malicious-download', expiresAt: null },
      { ruleType: 'ALLOW_DOMAIN', normalizedValue: 'false-positive.example', priority: 100, enabled: true, category: 'custom', expiresAt: null },
    ],
    ...overrides,
  });
  return payload;
}

export const update = (payload: PolicyPayload) => ({ type: 'POLICY_UPDATE', policyVersion: payload.policyVersion, payload });

/** In-memory DNR with Chromium's validation-relevant behaviour (atomic, unique ids). */
export class FakePlatform implements ExtensionPlatform {
  rules = new Map<number, DnrRule>();
  store = new Map<string, unknown>();
  failNextUpdate: string | null = null;
  unsupportedRegex = new Set<string>();
  updateCalls = 0;
  private seq = 0;
  clock = new Date('2026-10-28T12:00:00.000Z');

  readonly extensionOrigin = ORIGIN;
  readonly now = () => new Date(this.clock);
  readonly randomId = () => {
    const n = (++this.seq).toString(16).padStart(12, '0');
    return `aaaaaaaa-aaaa-4aaa-8aaa-${n}`;
  };

  readonly dnr = {
    getDynamicRules: async () => [...this.rules.values()].map((r) => structuredClone(r)),
    updateDynamicRules: async ({ removeRuleIds, addRules }: { removeRuleIds: number[]; addRules: DnrRule[] }) => {
      this.updateCalls++;
      if (this.failNextUpdate) {
        const msg = this.failNextUpdate;
        this.failNextUpdate = null;
        throw new Error(msg);
      }
      const next = new Map(this.rules);
      for (const id of removeRuleIds) next.delete(id);
      for (const r of addRules) {
        if (next.has(r.id)) throw new Error(`Rule with id ${r.id} does not have a unique ID.`);
        if (!Number.isInteger(r.id) || r.id < 1) throw new Error(`Invalid rule id ${r.id}`);
        next.set(r.id, structuredClone(r));
      }
      this.rules = next;
    },
    isRegexSupported: async (regex: string) => !this.unsupportedRegex.has(regex),
  };

  readonly storage = {
    get: async <T>(key: string) => structuredClone(this.store.get(key)) as T | undefined,
    set: async (key: string, value: unknown) => {
      this.store.set(key, structuredClone(value));
    },
  };
}

/**
 * Evaluates dynamic rules against a request following Chromium's DNR
 * semantics closely enough to assert enforcement outcomes: highest priority
 * wins; on ties allow > block > redirect.
 */
export function evaluate(rules: Iterable<DnrRule>, url: string, resourceType: ResourceType = 'main_frame') {
  const host = new URL(url).hostname;
  const matches: DnrRule[] = [];
  for (const r of rules) {
    const c = r.condition;
    if (c.resourceTypes && !c.resourceTypes.includes(resourceType)) continue;
    if (c.excludedResourceTypes?.includes(resourceType)) continue;
    if (c.requestDomains && !c.requestDomains.some((d) => host === d || host.endsWith(`.${d}`))) continue;
    if (c.regexFilter && !new RegExp(c.regexFilter, 'i').test(url)) continue;
    if (c.urlFilter) {
      const m = /^\|(.*)\|$/.exec(c.urlFilter);
      if (!m || url !== m[1]) continue;
    }
    matches.push(r);
  }
  const rank = { allow: 3, block: 2, redirect: 1 } as const;
  matches.sort((a, b) => b.priority - a.priority || rank[b.action.type] - rank[a.action.type]);
  const winner = matches[0];
  if (!winner) return { action: 'none' as const };
  if (winner.action.type === 'redirect') {
    const red = winner.action.redirect;
    const target =
      'regexSubstitution' in red
        ? url.replace(new RegExp(winner.condition.regexFilter!, 'i'), red.regexSubstitution.replace(/\\0/g, () => '$&'))
        : `${ORIGIN}${red.extensionPath}`;
    return { action: 'redirect' as const, target, ruleId: winner.id };
  }
  return { action: winner.action.type, ruleId: winner.id };
}

export class FakePort implements NativePort {
  sent: Record<string, unknown>[] = [];
  disconnected = false;
  private messageListeners: ((m: unknown) => void)[] = [];
  private disconnectListeners: ((e: string | null) => void)[] = [];
  postMessage(m: unknown) {
    if (this.disconnected) throw new Error('Attempting to use a disconnected port object');
    this.sent.push(structuredClone(m) as Record<string, unknown>);
  }
  onMessage(l: (m: unknown) => void) {
    this.messageListeners.push(l);
  }
  onDisconnect(l: (e: string | null) => void) {
    this.disconnectListeners.push(l);
  }
  disconnect() {
    this.disconnected = true;
  }
  /** Simulate the host. */
  deliver(m: unknown) {
    for (const l of this.messageListeners) l(m);
  }
  hostExit(error = 'Native host has exited.') {
    this.disconnected = true;
    for (const l of this.disconnectListeners) l(error);
  }
  ofType(type: string) {
    return this.sent.filter((m) => m.type === type);
  }
}

export const flush = () => new Promise((r) => setTimeout(r, 0));
