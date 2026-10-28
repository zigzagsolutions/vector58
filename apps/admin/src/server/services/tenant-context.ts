import 'server-only';
import { TENANT_CONTEXT_TTL_MINUTES, notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { PlatformActor } from '../auth/types';
import { withServiceTx } from '../db';
import type { RequestMeta } from '../http';

/**
 * Platform user explicitly enters a tenant. Requires
 * platform.support.enter_tenant (checked by the caller via
 * requirePlatformPermission). The user keeps their own identity; RLS grants
 * only the tenant-context permissions of their platform role(s). Audited in
 * the TENANT's audit log so customers can see who accessed their data.
 */
export async function enterTenantContext(
  actor: PlatformActor,
  organizationId: string,
  reason: string | null,
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const org = await db.query<{ name: string }>(`select name from public.organizations where id = $1`, [organizationId]);
    if (!org.rowCount) throw notFound('Organization not found');
    const ended = await db.query<{ id: string; organization_id: string }>(
      `update public.platform_tenant_contexts set ended_at = now()
       where actor_user_id = $1 and ended_at is null returning id, organization_id`,
      [actor.user.id],
    );
    for (const prev of ended.rows) {
      await recordAudit(db, {
        actor, organizationId: prev.organization_id, action: AuditAction.PLATFORM_ADMIN_EXITED_TENANT,
        targetType: 'tenant_context', targetId: prev.id, metadata: { reason: 'switched_tenant' }, request,
      });
    }
    const ctx = await db.query<{ id: string; expires_at: Date }>(
      `insert into public.platform_tenant_contexts (actor_user_id, organization_id, platform_roles, reason, expires_at)
       values ($1, $2, $3, $4, now() + make_interval(mins => $5)) returning id, expires_at`,
      [actor.user.id, organizationId, actor.platformRoles, reason, TENANT_CONTEXT_TTL_MINUTES],
    );
    const id = ctx.rows[0]!.id;
    await recordAudit(db, {
      actor,
      organizationId,
      action: AuditAction.PLATFORM_ADMIN_ENTERED_TENANT,
      targetType: 'organization',
      targetId: organizationId,
      tenantContextId: id,
      metadata: { reason, expiresAt: ctx.rows[0]!.expires_at.toISOString(), organizationName: org.rows[0]!.name },
      request,
    });
    return { contextId: id, organizationId, expiresAt: ctx.rows[0]!.expires_at.toISOString() };
  });
}

export async function exitTenantContext(actor: PlatformActor, request?: RequestMeta) {
  return withServiceTx(async (db) => {
    const ended = await db.query<{ id: string; organization_id: string }>(
      `update public.platform_tenant_contexts set ended_at = now()
       where actor_user_id = $1 and ended_at is null returning id, organization_id`,
      [actor.user.id],
    );
    for (const prev of ended.rows) {
      await recordAudit(db, {
        actor, organizationId: prev.organization_id, action: AuditAction.PLATFORM_ADMIN_EXITED_TENANT,
        targetType: 'tenant_context', targetId: prev.id, request,
      });
    }
    return { ended: ended.rowCount ?? 0 };
  });
}
