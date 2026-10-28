/**
 * Policy precedence (highest wins). Bands are spaced so that a rule's own
 * priority (0-999) orders rules *within* a band without ever crossing bands.
 *
 *   CRITICAL_PLATFORM (reserved) - non-overridable platform block (Phase 2)
 *   ORG_ALLOW                    - explicit organization allow exception
 *   ORG_BLOCK                    - explicit organization block
 *   GLOBAL_BLOCK                 - global confirmed-malicious intelligence
 *   (no rule)                    - default allow
 *
 * The DNR adapter in the extension maps these priorities 1:1 onto
 * declarativeNetRequest rule priorities, so the browser enforces exactly the
 * precedence documented in docs/policy-engine.md.
 */
export const PRIORITY_BANDS = {
  CRITICAL_PLATFORM: 4000,
  ORG_ALLOW: 3000,
  ORG_BLOCK: 2000,
  GLOBAL_BLOCK: 1000,
} as const;

export const BAND_WIDTH = 1000;

export type PrecedenceBand = keyof typeof PRIORITY_BANDS;

export function bandPriority(band: PrecedenceBand, rulePriority: number): number {
  const clamped = Math.max(0, Math.min(BAND_WIDTH - 1, Math.trunc(rulePriority)));
  return PRIORITY_BANDS[band] + clamped;
}

/** Evaluate the effective action for a hostname/url against compiled rules (reference implementation). */
export interface DecisionRule {
  readonly action: 'block' | 'allow';
  readonly priority: number;
}

export function decide<R extends DecisionRule>(matching: readonly R[]): { action: 'block' | 'allow'; rule: R | null } {
  let winner: R | null = null;
  for (const r of matching) {
    if (
      !winner ||
      r.priority > winner.priority ||
      // Chromium DNR tie-break: allow beats block at equal priority.
      (r.priority === winner.priority && r.action === 'allow' && winner.action === 'block')
    ) {
      winner = r;
    }
  }
  return winner ? { action: winner.action, rule: winner } : { action: 'allow', rule: null };
}
