import 'server-only';
import { DEVICE_AUTH_SCHEME, unauthenticated } from '@bsp/shared';
import type { DeviceActor } from './auth/types';
import { constantTimeEqualHex, sha256 } from './crypto';
import { withServiceTx } from './db';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Authenticates an endpoint: `Authorization: Device <deviceId>.<secret>`.
 * The organization is taken from the device record, never from the request.
 *
 * Extension point: Phase 2 replaces bearer secrets with a device keypair
 * (devices.public_key) and signed requests; only this function changes.
 */
export async function authenticateDevice(req: Request): Promise<DeviceActor> {
  const header = req.headers.get('authorization') ?? '';
  const m = header.match(new RegExp(`^${DEVICE_AUTH_SCHEME}\\s+([0-9a-fA-F-]{36})\\.([A-Za-z0-9_-]{20,200})$`));
  if (!m || !UUID_RE.test(m[1]!)) throw unauthenticated('Device credentials required');
  const [, deviceId, secret] = m as unknown as [string, string, string];

  const r = await withServiceTx((db) =>
    db.query(
      `select d.id, d.organization_id, d.hostname, d.agent_version, d.policy_id, d.credential_hash, d.status,
              o.status as org_status
       from public.devices d join public.organizations o on o.id = d.organization_id where d.id = $1`,
      [deviceId],
    ),
  );
  const d = r.rows[0];
  // Hash comparison always runs to keep timing uniform for unknown ids.
  const ok = constantTimeEqualHex(sha256(secret), d?.credential_hash ?? '0'.repeat(64));
  if (!d || !ok || d.status !== 'active' || d.org_status !== 'active') {
    throw unauthenticated('Device credentials are invalid or the device is disabled');
  }
  return {
    kind: 'device',
    deviceId: d.id,
    organizationId: d.organization_id,
    hostname: d.hostname,
    agentVersion: d.agent_version,
    policyId: d.policy_id,
  };
}
