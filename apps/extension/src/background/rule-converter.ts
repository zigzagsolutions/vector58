import type { CompiledRule } from '@bsp/policy-types';
import { ALL_RESOURCE_TYPES, type DnrRule } from './dnr-types';

/**
 * Converts compiled policy rules into declarativeNetRequest dynamic rules.
 *
 * Each policy rule N maps to deterministic DNR ids:
 *   2N     main_frame rule (block -> redirect to the block page; allow -> allow all types)
 *   2N + 1 every other resource type (block only)
 *
 * Policy priorities are used verbatim as DNR priorities, so Chromium enforces
 * the compiler's precedence (allow exception > org block > global block).
 * Main-frame blocks redirect to blocked.html so the user sees a branded page
 * and the extension can report URL_BLOCKED. Up to `regexBudget` rules use a
 * regex redirect that carries the original URL; the rest redirect without it
 * (Chromium allows at most 1000 regex rules).
 */
export const BLOCK_PAGE_PATH = '/blocked.html';
export const DEFAULT_REGEX_BUDGET = 900;

export const mainRuleId = (policyRuleId: number) => policyRuleId * 2;
export const subRuleId = (policyRuleId: number) => policyRuleId * 2 + 1;
export const policyRuleIdFromDnr = (dnrId: number) => Math.floor(dnrId / 2);

const RE2_SPECIAL = /[\\^$.|?*+()[\]{}/-]/g;
export const escapeRegex = (s: string) => s.replace(RE2_SPECIAL, '\\$&');

/** Regex matching the domain and all its subdomains, any scheme/port/path, tolerant of userinfo. */
export const domainRegex = (domain: string) =>
  `^https?://([^/?#@]*[.@])?${escapeRegex(domain)}(:[0-9]+)?([/?#].*)?$`;
export const exactUrlRegex = (url: string) => `^${escapeRegex(url)}$`;

export interface ConvertOptions {
  /** e.g. chrome-extension://<id> */
  readonly extensionOrigin: string;
  readonly regexBudget?: number;
  /** Optional runtime check (chrome.declarativeNetRequest.isRegexSupported). */
  readonly regexSupported?: (regex: string) => boolean;
}

export interface ConvertResult {
  readonly rules: DnrRule[];
  readonly regexRuleCount: number;
}

export function convertPolicyRules(
  rules: readonly CompiledRule[],
  opts: ConvertOptions,
): ConvertResult {
  const budget = opts.regexBudget ?? DEFAULT_REGEX_BUDGET;
  let regexUsed = 0;
  const out: DnrRule[] = [];
  // Spend the regex budget on the highest-precedence blocks first.
  const ordered = [...rules].sort((a, b) => b.priority - a.priority || a.id - b.id);

  for (const r of ordered) {
    if (r.action === 'allow') {
      out.push({
        id: mainRuleId(r.id),
        priority: r.priority,
        action: { type: 'allow' },
        condition:
          r.type === 'domain'
            ? { requestDomains: [r.value], resourceTypes: [...ALL_RESOURCE_TYPES] }
            : { regexFilter: exactUrlRegex(r.value), resourceTypes: [...ALL_RESOURCE_TYPES] },
      });
      continue;
    }

    const regex = r.type === 'domain' ? domainRegex(r.value) : exactUrlRegex(r.value);
    const useRegex = regexUsed < budget && (opts.regexSupported?.(regex) ?? true);
    if (useRegex) regexUsed++;
    const blockPage = `${opts.extensionOrigin}${BLOCK_PAGE_PATH}?r=${r.id}`;

    out.push({
      id: mainRuleId(r.id),
      priority: r.priority,
      action: {
        type: 'redirect',
        redirect: useRegex
          ? { regexSubstitution: `${blockPage}#\\0` }
          : { extensionPath: `${BLOCK_PAGE_PATH}?r=${r.id}` },
      },
      condition:
        r.type === 'domain'
          ? {
              requestDomains: [r.value],
              ...(useRegex ? { regexFilter: regex } : {}),
              resourceTypes: ['main_frame'],
            }
          : { regexFilter: regex, resourceTypes: ['main_frame'] },
    });

    const urlFilterSafe = !/[*^|]/.test(r.value);
    out.push({
      id: subRuleId(r.id),
      priority: r.priority,
      action: { type: 'block' },
      condition:
        r.type === 'domain'
          ? { requestDomains: [r.value], excludedResourceTypes: ['main_frame'] }
          : urlFilterSafe
            ? { urlFilter: `|${r.value}|`, excludedResourceTypes: ['main_frame'] }
            : { regexFilter: regex, excludedResourceTypes: ['main_frame'] },
    });
  }
  return { rules: out.sort((a, b) => a.id - b.id), regexRuleCount: regexUsed };
}

export interface RuleDiff {
  readonly removeRuleIds: number[];
  readonly addRules: DnrRule[];
  readonly unchanged: number;
}

/** Minimal update: remove obsolete or changed rules, add new or changed ones. */
export function diffRules(existing: readonly DnrRule[], next: readonly DnrRule[]): RuleDiff {
  const key = (r: DnrRule) => JSON.stringify(r);
  const prev = new Map(existing.map((r) => [r.id, key(r)]));
  const nextIds = new Set(next.map((r) => r.id));
  const removeRuleIds: number[] = [];
  const addRules: DnrRule[] = [];
  let unchanged = 0;
  for (const r of existing) if (!nextIds.has(r.id)) removeRuleIds.push(r.id);
  for (const r of next) {
    const p = prev.get(r.id);
    if (p === undefined) addRules.push(r);
    else if (p !== key(r)) {
      removeRuleIds.push(r.id);
      addRules.push(r);
    } else unchanged++;
  }
  return { removeRuleIds: removeRuleIds.sort((a, b) => a - b), addRules, unchanged };
}
