import 'server-only';
import type { TenantPermission } from '@bsp/auth-permissions';
import { AppError, conflict, forbidden, notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { PlatformActor, TenantActor } from '../auth/types';
import { withServiceTx, withUserTx, type Db } from '../db';
import type { RequestMeta } from '../http';
import type { IdentityDirectory } from './identity';

export interface TenantUserRow {
  userId: string;
  email: string;
  displayName: string | null;
  status: string;
  roles: string[];
  addedAt: string;
}

export async function listTenantUsers(actor: TenantActor): Promise<TenantUserRow[]> {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select ou.user_id, p.email, p.display_name, ou.status, ou.added_at,
              coalesce(array_agg(r.key order by r.key) filter (where r.key is not null), '{}') as roles
       from public.organization_users ou
       join public.profiles p on p.id = ou.user_id
       left join public.organization_user_roles our on our.organization_id = ou.organization_id and our.user_id = ou.user_id
       left join public.roles r on r.id = our.role_id
       where ou.organization_id = $1 and ou.status <> 'removed'
       group by ou.user_id, p.email, p.display_name, ou.status, ou.added_at
       order by p.email`,
      [actor.organizationId],
    ),
  );
  return r.rows.map((u) => ({
    userId: u.user_id,
    email: u.email,
    displayName: u.display_name,
    status: u.status,
    roles: u.roles,
    addedAt: u.added_at.toISOString(),
  }));
}

/** Who is managing tenant users: a tenant member/context actor, or a platform user with platform.users.manage. */
export type UserManager = TenantActor | PlatformActor;

async function rolePermissions(db: Db, roleKey: string): Promise<{ id: string; perms: Set<string> } | null> {
  const r = await db.query<{ id: string; perms: string[] }>(
    `select r.id, coalesce(array_agg(rp.permission_key) filter (where rp.permission_key is not null), '{}') as perms
     from public.roles r left join public.role_permissions rp on rp.role_id = r.id
     where r.key = $1 and r.scope = 'tenant' and r.organization_id is null group by r.id`,
    [roleKey],
  );
  const row = r.rows[0];
  return row ? { id: row.id, perms: new Set(row.perms) } : null;
}

/**
 * Privilege-escalation guard (no hard-coded role names): a tenant actor may
 * only grant or revoke roles whose permissions are a subset of their own.
 * Platform actors need platform.users.manage.
 */
function assertCanManageRole(manager: UserManager, rolePerms: Set<string>) {
  if (manager.kind === 'platform') {
    if (!manager.permissions.has('platform.users.manage')) throw forbidden();
    return;
  }
  if (!manager.permissions.has('tenant.users.write')) throw forbidden();
  for (const p of rolePerms) {
    if (!manager.permissions.has(p as TenantPermission)) {
      throw forbidden('You cannot grant or change a role with more privileges than your own');
    }
  }
}

const orgOf = (manager: UserManager, organizationId: string) => {
  if (manager.kind === 'tenant' && manager.organizationId !== organizationId) throw forbidden();
  return organizationId;
};

/** At least one active member must keep every tenant permission (prevents lock-out). */
async function assertOwnerRemains(db: Db, organizationId: string) {
  const r = await db.query(
    `select 1 from public.organization_users ou
     where ou.organization_id = $1 and ou.status = 'active'
       and (select count(distinct rp.permission_key) from public.organization_user_roles our
            join public.role_permissions rp on rp.role_id = our.role_id
            where our.organization_id = ou.organization_id and our.user_id = ou.user_id)
         = (select count(*) from public.permissions where scope = 'tenant')
     limit 1`,
    [organizationId],
  );
  const members = await db.query(`select 1 from public.organization_users where organization_id = $1 and status = 'active' limit 1`, [organizationId]);
  if (members.rowCount && !r.rowCount) {
    throw new AppError('CONFLICT', 'This change would leave the organization without an owner');
  }
}

export async function addTenantUser(
  manager: UserManager,
  organizationId: string,
  input: { email: string; roleKey: string },
  identity: IdentityDirectory,
  request?: RequestMeta,
) {
  orgOf(manager, organizationId);
  return withServiceTx(async (db) => {
    const org = await db.query(`select status from public.organizations where id = $1`, [organizationId]);
    if (!org.rowCount) throw notFound('Organization not found');
    const role = await rolePermissions(db, input.roleKey);
    if (!role) throw new AppError('VALIDATION_FAILED', `Unknown tenant role "${input.roleKey}"`);
    assertCanManageRole(manager, role.perms);

    const userId = await identity.findOrInviteUser(db, input.email);
    const existing = await db.query<{ status: string }>(
      `select status from public.organization_users where organization_id = $1 and user_id = $2`,
      [organizationId, userId],
    );
    if (existing.rows[0]?.status === 'active') throw conflict('User is already a member of this organization');
    await db.query(
      `insert into public.organization_users (organization_id, user_id, status, added_by)
       values ($1, $2, 'active', $3)
       on conflict (organization_id, user_id) do update
         set status = 'active', added_by = excluded.added_by, added_at = now(), removed_at = null, removed_by = null`,
      [organizationId, userId, manager.user.id],
    );
    await db.query(
      `insert into public.organization_user_roles (organization_id, user_id, role_id, assigned_by) values ($1, $2, $3, $4)
       on conflict do nothing`,
      [organizationId, userId, role.id, manager.user.id],
    );
    await recordAudit(db, {
      actor: manager, organizationId, action: AuditAction.TENANT_USER_ADDED, targetType: 'user', targetId: userId,
      metadata: { email: input.email }, request,
    });
    await recordAudit(db, {
      actor: manager, organizationId, action: AuditAction.TENANT_ROLE_ASSIGNED, targetType: 'user', targetId: userId,
      metadata: { role: input.roleKey }, request,
    });
    return { userId };
  });
}

async function currentRoleKeysAndPerms(db: Db, organizationId: string, userId: string) {
  const r = await db.query<{ key: string; perms: string[] }>(
    `select r.key, coalesce(array_agg(rp.permission_key) filter (where rp.permission_key is not null), '{}') as perms
     from public.organization_user_roles our join public.roles r on r.id = our.role_id
     left join public.role_permissions rp on rp.role_id = r.id
     where our.organization_id = $1 and our.user_id = $2 group by r.key`,
    [organizationId, userId],
  );
  return r.rows;
}

export async function changeTenantUserRole(
  manager: UserManager,
  organizationId: string,
  userId: string,
  roleKey: string,
  request?: RequestMeta,
) {
  orgOf(manager, organizationId);
  return withServiceTx(async (db) => {
    const member = await db.query(
      `select 1 from public.organization_users where organization_id = $1 and user_id = $2 and status = 'active' for update`,
      [organizationId, userId],
    );
    if (!member.rowCount) throw notFound('User is not a member of this organization');
    const role = await rolePermissions(db, roleKey);
    if (!role) throw new AppError('VALIDATION_FAILED', `Unknown tenant role "${roleKey}"`);
    assertCanManageRole(manager, role.perms);
    const current = await currentRoleKeysAndPerms(db, organizationId, userId);
    for (const c of current) assertCanManageRole(manager, new Set(c.perms));

    await db.query(`delete from public.organization_user_roles where organization_id = $1 and user_id = $2`, [organizationId, userId]);
    await db.query(
      `insert into public.organization_user_roles (organization_id, user_id, role_id, assigned_by) values ($1, $2, $3, $4)`,
      [organizationId, userId, role.id, manager.user.id],
    );
    await assertOwnerRemains(db, organizationId);
    await recordAudit(db, {
      actor: manager, organizationId, action: AuditAction.TENANT_ROLE_ASSIGNED, targetType: 'user', targetId: userId,
      metadata: { role: roleKey, previousRoles: current.map((c) => c.key) }, request,
    });
  });
}

export async function removeTenantUser(manager: UserManager, organizationId: string, userId: string, request?: RequestMeta) {
  orgOf(manager, organizationId);
  return withServiceTx(async (db) => {
    const current = await currentRoleKeysAndPerms(db, organizationId, userId);
    const member = await db.query(
      `update public.organization_users set status = 'removed', removed_at = now(), removed_by = $3
       where organization_id = $1 and user_id = $2 and status <> 'removed' returning id`,
      [organizationId, userId, manager.user.id],
    );
    if (!member.rowCount) throw notFound('User is not a member of this organization');
    for (const c of current) assertCanManageRole(manager, new Set(c.perms));
    if (manager.kind === 'platform' && !manager.permissions.has('platform.users.manage')) throw forbidden();
    if (manager.kind === 'tenant' && !manager.permissions.has('tenant.users.write')) throw forbidden();
    await db.query(`delete from public.organization_user_roles where organization_id = $1 and user_id = $2`, [organizationId, userId]);
    await assertOwnerRemains(db, organizationId);
    await recordAudit(db, {
      actor: manager, organizationId, action: AuditAction.TENANT_USER_REMOVED, targetType: 'user', targetId: userId,
      metadata: { previousRoles: current.map((c) => c.key) }, request,
    });
  });
}
