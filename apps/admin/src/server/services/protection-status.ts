import { DEVICE_OFFLINE_AFTER_SECONDS } from '@bsp/shared';
import type { ProtectionStatus } from '@bsp/policy-types';

/** Grace period after a publish before a device that has not picked it up is flagged. */
export const POLICY_OUTDATED_GRACE_SECONDS = 600;
/** A browser client is considered connected if it reported within this window. */
export const BROWSER_CLIENT_STALE_SECONDS = DEVICE_OFFLINE_AFTER_SECONDS;

export interface ProtectionInput {
  readonly status: 'active' | 'disabled';
  readonly enrolledAt: Date | null;
  readonly lastHeartbeatAt: Date | null;
  readonly policyVersion: number | null;
  readonly latestPolicyVersion: number | null;
  readonly latestPublishedAt: Date | null;
  readonly browserClients: readonly {
    nativeConnected: boolean;
    policyVersion: number | null;
    lastSeenAt: Date;
  }[];
  readonly now: Date;
}

/**
 * Protection status, evaluated in order:
 *  never_enrolled  - inventory record with no enrollment (reserved for device import)
 *  offline         - disabled, or no heartbeat within DEVICE_OFFLINE_AFTER_SECONDS
 *  policy_outdated - agent is behind the latest published version beyond the grace period
 *  degraded        - no connected browser extension, or an extension lags the agent's policy
 *  protected       - otherwise
 */
export function computeProtectionStatus(d: ProtectionInput): ProtectionStatus {
  if (!d.enrolledAt) return 'never_enrolled';
  const ageSec = (t: Date) => (d.now.getTime() - t.getTime()) / 1000;
  if (
    d.status === 'disabled' ||
    !d.lastHeartbeatAt ||
    ageSec(d.lastHeartbeatAt) > DEVICE_OFFLINE_AFTER_SECONDS
  ) {
    return 'offline';
  }
  if (
    d.latestPolicyVersion !== null &&
    (d.policyVersion ?? 0) < d.latestPolicyVersion &&
    (!d.latestPublishedAt || ageSec(d.latestPublishedAt) > POLICY_OUTDATED_GRACE_SECONDS)
  ) {
    return 'policy_outdated';
  }
  const live = d.browserClients.filter(
    (c) => c.nativeConnected && ageSec(c.lastSeenAt) <= BROWSER_CLIENT_STALE_SECONDS,
  );
  if (live.length === 0) return 'degraded';
  if (d.policyVersion !== null && live.some((c) => (c.policyVersion ?? 0) < d.policyVersion!))
    return 'degraded';
  return 'protected';
}
