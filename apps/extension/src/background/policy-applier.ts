import { verifyPolicyChecksum } from '@bsp/policy-engine';
import { PolicyUpdateMessageSchema, type PolicyStatusMessage } from '@bsp/policy-types';
import { convertPolicyRules } from './rule-converter';
import { diffRules } from './rule-converter';
import type { ExtensionPlatform } from './platform';
import type { ExtensionState } from './state';

export interface ApplyOutcome {
  readonly status: PolicyStatusMessage;
  readonly error?: string;
}

/**
 * Apply a POLICY_UPDATE: validate schema -> verify checksum -> reject
 * rollbacks -> convert to DNR -> diff -> atomic updateDynamicRules -> record.
 *
 * On ANY failure the previously applied dynamic rules are left untouched
 * (updateDynamicRules is atomic), so protection never drops because of a bad
 * or partial update.
 */
export async function applyPolicyUpdate(
  raw: unknown,
  platform: ExtensionPlatform,
  state: ExtensionState,
): Promise<ApplyOutcome> {
  const now = platform.now().toISOString();
  const current = await state.getPolicy();
  const fail = (error: string, version: number | null = null): ApplyOutcome => ({
    error,
    status: {
      type: 'POLICY_STATUS',
      policyVersion: version ?? current?.policyVersion ?? null,
      status: 'failed',
      ruleCount: current?.ruleCount ?? 0,
      error,
      appliedAt: now,
    },
  });

  const parsed = PolicyUpdateMessageSchema.safeParse(raw);
  if (!parsed.success)
    return fail(
      `Invalid POLICY_UPDATE: ${parsed.error.issues
        .slice(0, 3)
        .map((i) => `${i.path.join('.')}: ${i.message}`)
        .join('; ')}`,
    );
  const { payload } = parsed.data;
  if (parsed.data.policyVersion !== payload.policyVersion)
    return fail('Envelope and payload policy versions differ', payload.policyVersion);
  if (!(await verifyPolicyChecksum(payload)))
    return fail('Policy checksum verification failed', payload.policyVersion);
  if (current && current.organizationId !== payload.organizationId) {
    // A device belongs to exactly one tenant; switching tenants requires re-enrollment.
    return fail('Policy organization does not match the applied policy', payload.policyVersion);
  }
  if (current && payload.policyVersion < current.policyVersion) {
    return fail(
      `Refusing rollback from v${current.policyVersion} to v${payload.policyVersion}`,
      payload.policyVersion,
    );
  }
  if (
    current &&
    payload.policyVersion === current.policyVersion &&
    payload.checksum === current.checksum
  ) {
    return {
      status: {
        type: 'POLICY_STATUS',
        policyVersion: current.policyVersion,
        status: 'unchanged',
        ruleCount: current.ruleCount,
        appliedAt: current.appliedAt,
      },
    };
  }

  try {
    const regexOk = new Map<string, boolean>();
    const { rules: dnrRules } = convertPolicyRules(payload.rules, {
      extensionOrigin: platform.extensionOrigin,
      regexSupported: (re) => regexOk.get(re) ?? true,
    });
    if (platform.dnr.isRegexSupported) {
      // Pre-check regexes; unsupported ones fall back to non-capturing redirects.
      for (const r of dnrRules) {
        if (r.condition.regexFilter && r.action.type === 'redirect') {
          regexOk.set(
            r.condition.regexFilter,
            await platform.dnr.isRegexSupported(r.condition.regexFilter),
          );
        }
      }
    }
    const final = regexOk.size
      ? convertPolicyRules(payload.rules, {
          extensionOrigin: platform.extensionOrigin,
          regexSupported: (re) => regexOk.get(re) ?? true,
        }).rules
      : dnrRules;
    const existing = await platform.dnr.getDynamicRules();
    const diff = diffRules(existing, final);
    await platform.dnr.updateDynamicRules({
      removeRuleIds: diff.removeRuleIds,
      addRules: diff.addRules,
    });

    await state.setPolicy({
      policyVersion: payload.policyVersion,
      checksum: payload.checksum,
      organizationId: payload.organizationId,
      appliedAt: now,
      ruleCount: payload.rules.length,
      dnrRuleCount: final.length,
      rules: payload.rules.map(({ id, type, value, action, category }) => ({
        id,
        type,
        value,
        action,
        category,
      })),
    });
    return {
      status: {
        type: 'POLICY_STATUS',
        policyVersion: payload.policyVersion,
        status: 'applied',
        ruleCount: payload.rules.length,
        appliedAt: now,
      },
    };
  } catch (e) {
    return fail(
      `Failed to apply DNR rules: ${(e as Error).message ?? String(e)}`,
      payload.policyVersion,
    );
  }
}
