import 'server-only';
import type { CreateOrganizationRequest } from '@bsp/policy-types';
import { conflict, notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { PlatformActor } from '../auth/types';
import { withServiceTx, withUserTx } from '../db';
import type { RequestMeta } from '../http';

export interface CustomerRow {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'disabled';
  createdAt: string;
  deviceCount: number;
  activeUsers: number;
  latestPolicyVersion: number | null;
  lastActivity: string | null;
}

/** Customer list for platform users. Runs under RLS (platform.tenants.read). */
export async function listOrganizations(actor: PlatformActor): Promise<CustomerRow[]> {
  // Aggregates over tenant tables need the service connection (platform users
  // cannot read tenant rows outside a context); we only expose counts.
  const visible = await withUserTx(actor.user.id, (db) =>
    db.query<{ id: string }>(`select id from public.organizations`),
  );
  const ids = visible.rows.map((r) => r.id);
  if (ids.length === 0) return [];
  const r = await withServiceTx((db) =>
    db.query(
      `select o.id, o.name, o.slug, o.status, o.created_at,
              (select count(*) from public.devices d where d.organization_id = o.id and d.status = 'active')::int as device_count,
              (select count(*) from public.organization_users ou where ou.organization_id = o.id and ou.status = 'active')::int as active_users,
              (select max(p.current_version_number) from public.policies p where p.organization_id = o.id) as latest_policy_version,
              greatest(
                (select max(d.last_heartbeat_at) from public.devices d where d.organization_id = o.id),
                (select max(a.occurred_at) from public.audit_events a where a.organization_id = o.id)
              ) as last_activity
       from public.organizations o where o.id = any($1::uuid[]) order by o.name`,
      [ids],
    ),
  );
  return r.rows.map((o) => ({
    id: o.id,
    name: o.name,
    slug: o.slug,
    status: o.status,
    createdAt: o.created_at.toISOString(),
    deviceCount: o.device_count,
    activeUsers: o.active_users,
    latestPolicyVersion: o.latest_policy_version,
    lastActivity: o.last_activity?.toISOString() ?? null,
  }));
}

export async function getOrganization(actor: PlatformActor, organizationId: string) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select id, name, slug, status, created_at, disabled_at from public.organizations where id = $1`,
      [organizationId],
    ),
  );
  const o = r.rows[0];
  if (!o) throw notFound('Organization not found');
  return {
    id: o.id as string,
    name: o.name as string,
    slug: o.slug as string,
    status: o.status as string,
    createdAt: (o.created_at as Date).toISOString(),
  };
}

/** Creates a tenant with its default policy. Tenant #1 (Internal) is created the same way. */
export async function createOrganization(
  actor: PlatformActor,
  input: CreateOrganizationRequest,
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const exists = await db.query(`select 1 from public.organizations where slug = $1`, [
      input.slug,
    ]);
    if (exists.rowCount) throw conflict(`Slug "${input.slug}" is already in use`);
    const org = await db.query<{ id: string; created_at: Date }>(
      `insert into public.organizations (name, slug, created_by) values ($1, $2, $3) returning id, created_at`,
      [input.name, input.slug, actor.user.id],
    );
    const id = org.rows[0]!.id;
    await db.query(
      `insert into public.policies (organization_id, name, description, is_default, created_by)
       values ($1, 'Default Policy', 'Applied to all enrolled devices', true, $2)`,
      [id, actor.user.id],
    );
    await recordAudit(db, {
      actor,
      organizationId: id,
      action: AuditAction.TENANT_CREATED,
      targetType: 'organization',
      targetId: id,
      metadata: { name: input.name, slug: input.slug },
      request,
    });
    return {
      id,
      name: input.name,
      slug: input.slug,
      status: 'active' as const,
      createdAt: org.rows[0]!.created_at.toISOString(),
    };
  });
}

/** Soft-disable (never hard-delete) a tenant. Members immediately lose access via RLS. */
export async function setOrganizationStatus(
  actor: PlatformActor,
  organizationId: string,
  status: 'active' | 'disabled',
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `update public.organizations
         set status = $2,
             disabled_at = case when $2 = 'disabled' then now() else null end,
             disabled_by = case when $2 = 'disabled' then $3::uuid else null end
       where id = $1 and status <> $2 returning id`,
      [organizationId, status, actor.user.id],
    );
    if (r.rowCount === 0) {
      const exists = await db.query(`select 1 from public.organizations where id = $1`, [
        organizationId,
      ]);
      if (!exists.rowCount) throw notFound('Organization not found');
      return { changed: false };
    }
    await recordAudit(db, {
      actor,
      organizationId,
      action: status === 'disabled' ? AuditAction.TENANT_DISABLED : AuditAction.TENANT_ENABLED,
      targetType: 'organization',
      targetId: organizationId,
      request,
    });
    return { changed: true };
  });
}
