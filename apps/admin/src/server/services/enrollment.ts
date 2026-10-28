import 'server-only';
import type { EnrollmentRequest, EnrollmentResponse } from '@bsp/policy-types';
import { AGENT_HEARTBEAT_INTERVAL_SECONDS, AppError, notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { TenantActor } from '../auth/types';
import { generateToken, sha256 } from '../crypto';
import { withServiceTx, withUserTx } from '../db';
import type { RequestMeta } from '../http';

export const POLICY_POLL_INTERVAL_SECONDS = 60;

export async function listEnrollmentTokens(actor: TenantActor) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select id, token_prefix, description, max_uses, use_count, expires_at, status, created_at
       from public.enrollment_tokens where organization_id = $1 order by created_at desc`,
      [actor.organizationId],
    ),
  );
  return r.rows.map((t) => ({
    id: t.id as string,
    tokenPrefix: t.token_prefix as string,
    description: t.description as string | null,
    maxUses: t.max_uses as number,
    useCount: t.use_count as number,
    expiresAt: (t.expires_at as Date).toISOString(),
    status: (t.expires_at as Date) < new Date() && t.status === 'active' ? 'expired' : (t.status as string),
    createdAt: (t.created_at as Date).toISOString(),
  }));
}

/** Create a token. The plaintext is returned exactly once and only its sha256 is stored. */
export async function createEnrollmentToken(
  actor: TenantActor,
  input: { description?: string; maxUses: number; expiresInHours: number },
  request?: RequestMeta,
) {
  const token = generateToken('bspe');
  return withServiceTx(async (db) => {
    const r = await db.query<{ id: string; expires_at: Date }>(
      `insert into public.enrollment_tokens (organization_id, token_hash, token_prefix, description, max_uses, expires_at, created_by)
       values ($1, $2, $3, $4, $5, now() + make_interval(hours => $6), $7) returning id, expires_at`,
      [actor.organizationId, sha256(token), token.slice(0, 12), input.description ?? null, input.maxUses, input.expiresInHours, actor.user.id],
    );
    await recordAudit(db, {
      actor, organizationId: actor.organizationId, action: AuditAction.ENROLLMENT_TOKEN_CREATED,
      targetType: 'enrollment_token', targetId: r.rows[0]!.id, metadata: { maxUses: input.maxUses, expiresInHours: input.expiresInHours }, request,
    });
    return { id: r.rows[0]!.id, token, expiresAt: r.rows[0]!.expires_at.toISOString() };
  });
}

export async function revokeEnrollmentToken(actor: TenantActor, tokenId: string, request?: RequestMeta) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `update public.enrollment_tokens set status = 'revoked', revoked_at = now(), revoked_by = $3
       where id = $1 and organization_id = $2 and status = 'active' returning id`,
      [tokenId, actor.organizationId, actor.user.id],
    );
    if (!r.rowCount) throw notFound('Enrollment token not found');
    await recordAudit(db, {
      actor, organizationId: actor.organizationId, action: AuditAction.ENROLLMENT_TOKEN_REVOKED, targetType: 'enrollment_token', targetId: tokenId, request,
    });
  });
}

const invalidToken = () => new AppError('UNAUTHENTICATED', 'Enrollment token is invalid, expired or exhausted');

/**
 * Device enrollment. The tenant is derived ONLY from the enrollment token;
 * any organization hint from the device is ignored (and not even parsed).
 * Re-enrolling the same installation id rotates its credential.
 */
export async function enrollDevice(input: EnrollmentRequest, publicIp: string | null): Promise<EnrollmentResponse> {
  const deviceSecret = generateToken('bspd');
  return withServiceTx(async (db) => {
    const t = await db.query(
      `select t.id, t.organization_id, t.max_uses, t.use_count, t.expires_at, t.status, o.name, o.status as org_status, o.device_limit
       from public.enrollment_tokens t join public.organizations o on o.id = t.organization_id
       where t.token_hash = $1 for update of t`,
      [sha256(input.enrollmentToken)],
    );
    const token = t.rows[0];
    if (!token || token.status !== 'active' || token.expires_at <= new Date() || token.use_count >= token.max_uses) {
      console.warn(JSON.stringify({ level: 'warn', msg: 'enrollment_rejected', reason: token ? 'inactive_or_expired' : 'unknown_token' }));
      throw invalidToken();
    }
    if (token.org_status !== 'active') throw invalidToken();
    if (token.device_limit) {
      const c = await db.query<{ n: number }>(`select count(*)::int as n from public.devices where organization_id = $1 and status = 'active'`, [token.organization_id]);
      if ((c.rows[0]?.n ?? 0) >= token.device_limit) throw new AppError('FORBIDDEN', 'Device limit reached for this organization');
    }
    const orgId: string = token.organization_id;

    const d = await db.query<{ id: string; enrolled_at: Date; inserted: boolean }>(
      `insert into public.devices (organization_id, installation_id, hostname, os_version, agent_version, local_ip,
                                   public_ip, machine, credential_hash, enrollment_token_id, public_key)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       on conflict (organization_id, installation_id) do update set
         hostname = excluded.hostname, os_version = excluded.os_version, agent_version = excluded.agent_version,
         local_ip = excluded.local_ip, public_ip = excluded.public_ip, machine = excluded.machine,
         credential_hash = excluded.credential_hash, credential_rotated_at = now(),
         enrollment_token_id = excluded.enrollment_token_id, status = 'active', enrolled_at = now(),
         disabled_at = null, disabled_by = null
       returning id, enrolled_at, (xmax = 0) as inserted`,
      [orgId, input.installationId, input.hostname, input.osVersion, input.agentVersion, input.localIp ?? null,
       publicIp, JSON.stringify(input.machine ?? {}), sha256(deviceSecret), token.id, input.publicKey ?? null],
    );
    const device = d.rows[0]!;
    await db.query(
      `update public.enrollment_tokens set use_count = use_count + 1,
              status = case when use_count + 1 >= max_uses then 'exhausted' else status end
       where id = $1`,
      [token.id],
    );
    await db.query(
      `insert into public.security_events (organization_id, device_id, source_event_id, event_type, occurred_at,
                                           agent_version, hostname, details)
       values ($1, $2, gen_random_uuid(), 'DEVICE_ENROLLED', now(), $3, $4, $5)`,
      [orgId, device.id, input.agentVersion, input.hostname, JSON.stringify({ reenrolled: !device.inserted, publicIp })],
    );
    await recordAudit(db, {
      actor: { kind: 'device', deviceId: device.id, organizationId: orgId, hostname: input.hostname, agentVersion: input.agentVersion, policyId: null },
      organizationId: orgId,
      action: AuditAction.DEVICE_ENROLLED,
      targetType: 'device',
      targetId: device.id,
      metadata: { hostname: input.hostname, tokenId: token.id, reenrolled: !device.inserted },
      request: { ip: publicIp, userAgent: null },
    });
    return {
      deviceId: device.id,
      organizationId: orgId,
      organizationName: token.name,
      deviceSecret,
      heartbeatIntervalSeconds: AGENT_HEARTBEAT_INTERVAL_SECONDS,
      policyPollIntervalSeconds: POLICY_POLL_INTERVAL_SECONDS,
      enrolledAt: device.enrolled_at.toISOString(),
    };
  });
}
