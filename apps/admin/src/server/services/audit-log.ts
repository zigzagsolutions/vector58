import 'server-only';
import type { PlatformActor, TenantActor } from '../auth/types';
import { withUserTx } from '../db';

export interface AuditRow {
  id: string;
  organizationId: string | null;
  organizationName: string | null;
  actorEmail: string | null;
  actorDeviceId: string | null;
  actorScope: string;
  platformRole: string | null;
  tenantRole: string | null;
  tenantContextId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  occurredAt: string;
  ipAddress: string | null;
  metadata: Record<string, unknown>;
}

const SELECT = `select a.id, a.organization_id, o.name as organization_name, coalesce(a.actor_email, p.email) as actor_email, a.actor_device_id,
       a.actor_scope, a.platform_role, a.tenant_role, a.tenant_context_id, a.action, a.target_type, a.target_id,
       a.occurred_at, a.ip_address, a.metadata
  from public.audit_events a
  left join public.organizations o on o.id = a.organization_id
  left join public.profiles p on p.id = a.actor_user_id`;

const map = (a: Record<string, unknown>): AuditRow => ({
  id: a.id as string,
  organizationId: a.organization_id as string | null,
  organizationName: a.organization_name as string | null,
  actorEmail: a.actor_email as string | null,
  actorDeviceId: a.actor_device_id as string | null,
  actorScope: a.actor_scope as string,
  platformRole: a.platform_role as string | null,
  tenantRole: a.tenant_role as string | null,
  tenantContextId: a.tenant_context_id as string | null,
  action: a.action as string,
  targetType: a.target_type as string | null,
  targetId: a.target_id as string | null,
  occurredAt: (a.occurred_at as Date).toISOString(),
  ipAddress: a.ip_address as string | null,
  metadata: a.metadata as Record<string, unknown>,
});

/** Tenant audit log (RLS: tenant.audit.read, own organization only). */
export async function listTenantAudit(actor: TenantActor, filters: { action?: string; limit?: number } = {}) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(`${SELECT} where a.organization_id = $1 and ($2::text is null or a.action = $2) order by a.occurred_at desc limit $3`, [
      actor.organizationId,
      filters.action ?? null,
      filters.limit ?? 200,
    ]),
  );
  return r.rows.map(map);
}

/** Platform audit log across tenants (RLS: platform.audit.read). */
export async function listPlatformAudit(
  actor: PlatformActor,
  filters: { organizationId?: string; action?: string; scope?: string; limit?: number } = {},
) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `${SELECT} where ($1::uuid is null or a.organization_id = $1) and ($2::text is null or a.action = $2)
         and ($3::text is null or a.actor_scope = $3)
       order by a.occurred_at desc limit $4`,
      [filters.organizationId ?? null, filters.action ?? null, filters.scope ?? null, filters.limit ?? 300],
    ),
  );
  return r.rows.map(map);
}
