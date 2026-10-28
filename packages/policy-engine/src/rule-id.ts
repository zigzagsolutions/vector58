import { MAX_POLICY_RULE_ID } from '@bsp/policy-types';

/** 32-bit FNV-1a; synchronous and identical in every JS runtime. */
export function fnv1a32(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/**
 * Deterministic rule ids: derived from the rule identity so the same rule
 * keeps the same id across policy versions (stable DNR ids => minimal churn
 * in the browser and stable references in security events). Collisions are
 * resolved by linear probing over identities processed in sorted order.
 */
export function assignRuleIds(identities: readonly string[]): Map<string, number> {
  const used = new Set<number>();
  const out = new Map<string, number>();
  for (const identity of [...identities].sort()) {
    if (out.has(identity)) continue;
    let id = (fnv1a32(identity) % MAX_POLICY_RULE_ID) + 1;
    while (used.has(id)) id = (id % MAX_POLICY_RULE_ID) + 1;
    used.add(id);
    out.set(identity, id);
  }
  return out;
}
