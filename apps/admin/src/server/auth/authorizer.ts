import 'server-only';
import {
  isPlatformPermission,
  isTenantPermission,
  type PlatformPermission,
  type TenantPermission,
} from '@bsp/auth-permissions';
import { AppError, forbidden, unauthenticated } from '@bsp/shared';
import { withServiceTx, withUserTx } from '../db';
import type { PlatformActor, SessionProvider, SessionUser, TenantActor, TenantContext } from './types';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Server-side authorization. Permission evaluation is delegated to the same
 * SQL functions that back RLS (public.has_platform_permission /
 * public.permitted_organization_ids), executed with the caller's identity,
 * so the API layer and the database can never disagree.
 *
 * Organization ids arriving from the browser are treated as *requests*; access
 * is always re-derived from the authenticated user.
 */
export class Authorizer {
  private userPromise: Promise<SessionUser | null> | undefined;

  constructor(private readonly sessions: SessionProvider) {}

  private currentUser(): Promise<SessionUser | null> {
    this.userPromise ??= this.sessions.getUser();
    return this.userPromise;
  }

  async requireAuthenticatedUser(): Promise<SessionUser> {
    const user = await this.currentUser();
    if (!user) throw unauthenticated();
    const active = await withServiceTx((db) =>
      db.query(`select 1 from public.profiles where id = $1 and status = 'active'`, [user.id]),
    );
    if (active.rowCount === 0) throw forbidden('Account is disabled');
    return user;
  }

  async platformAccess(user: SessionUser): Promise<{ roles: string[]; permissions: Set<PlatformPermission> }> {
    return withUserTx(user.id, async (db) => {
      const roles = await db.query<{ key: string }>(
        `select r.key from public.platform_user_roles pur join public.roles r on r.id = pur.role_id
         where pur.user_id = $1 order by r.key`,
        [user.id],
      );
      const perms = await db.query<{ key: string }>(
        `select key from public.permissions where scope = 'platform' and public.has_platform_permission(key)`,
      );
      return {
        roles: roles.rows.map((r) => r.key),
        permissions: new Set(perms.rows.map((p) => p.key).filter(isPlatformPermission)),
      };
    });
  }

  async requirePlatformPermission(permission: PlatformPermission): Promise<PlatformActor> {
    const user = await this.requireAuthenticatedUser();
    const access = await this.platformAccess(user);
    if (!access.permissions.has(permission)) throw forbidden();
    return { kind: 'platform', user, platformRoles: access.roles, permissions: access.permissions };
  }

  /** Any platform role at all (used for routing to the platform console). */
  async requirePlatformUser(): Promise<PlatformActor> {
    const user = await this.requireAuthenticatedUser();
    const access = await this.platformAccess(user);
    if (access.roles.length === 0) throw forbidden();
    return { kind: 'platform', user, platformRoles: access.roles, permissions: access.permissions };
  }

  async resolveTenantContext(): Promise<TenantContext | null> {
    const user = await this.currentUser();
    if (!user) return null;
    const r = await withServiceTx((db) =>
      db.query<{
        id: string;
        organization_id: string;
        name: string;
        platform_roles: string[];
        started_at: Date;
        expires_at: Date;
      }>(
        `select c.id, c.organization_id, o.name, c.platform_roles, c.started_at, c.expires_at
         from public.platform_tenant_contexts c join public.organizations o on o.id = c.organization_id
         where c.actor_user_id = $1 and c.ended_at is null and c.expires_at > now()`,
        [user.id],
      ),
    );
    const row = r.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      actorUserId: user.id,
      organizationId: row.organization_id,
      organizationName: row.name,
      platformRoles: row.platform_roles,
      startedAt: row.started_at.toISOString(),
      expiresAt: row.expires_at.toISOString(),
    };
  }

  /** Resolve the caller's standing in an organization, or throw. */
  async requireTenantMembership(organizationId: string): Promise<TenantActor> {
    const user = await this.requireAuthenticatedUser();
    if (!UUID_RE.test(organizationId)) throw new AppError('NOT_FOUND', 'Organization not found');

    const result = await withUserTx(user.id, async (db) => {
      const org = await db.query<{ name: string; status: string }>(
        `select name, status from public.organizations where id = $1`,
        [organizationId],
      );
      const perms = await db.query<{ p: string }>(`select public.my_tenant_permissions($1) as p`, [organizationId]);
      const membership = await db.query<{ key: string }>(
        `select r.key from public.organization_users ou
         join public.organization_user_roles our on our.organization_id = ou.organization_id and our.user_id = ou.user_id
         join public.roles r on r.id = our.role_id
         where ou.organization_id = $1 and ou.user_id = $2 and ou.status = 'active'`,
        [organizationId, user.id],
      );
      return { org: org.rows[0], perms: perms.rows.map((r) => r.p), tenantRoles: membership.rows.map((r) => r.key) };
    });

    // Membership and context both yield zero permissions when access is absent;
    // respond NOT_FOUND so ids of other tenants are not confirmable.
    if (!result.org || result.perms.length === 0) throw new AppError('NOT_FOUND', 'Organization not found');

    const isMember = result.tenantRoles.length > 0 && result.org.status === 'active';
    let ctx: TenantContext | null = null;
    let platformRoles: string[] = [];
    if (!isMember) {
      ctx = await this.resolveTenantContext();
      if (!ctx || ctx.organizationId !== organizationId) throw new AppError('NOT_FOUND', 'Organization not found');
      platformRoles = [...ctx.platformRoles];
    }

    return {
      kind: 'tenant',
      user,
      organizationId,
      organizationName: result.org.name,
      permissions: new Set(result.perms.filter(isTenantPermission)),
      via: isMember ? 'membership' : 'platform_context',
      tenantRoles: result.tenantRoles,
      platformRoles,
      contextId: ctx?.id ?? null,
    };
  }

  async requireTenantPermission(organizationId: string, permission: TenantPermission): Promise<TenantActor> {
    const actor = await this.requireTenantMembership(organizationId);
    if (!actor.permissions.has(permission)) throw forbidden();
    return actor;
  }

  /** Organizations the user is an active member of (for the org switcher). */
  async myOrganizations(): Promise<{ id: string; name: string; slug: string }[]> {
    const user = await this.requireAuthenticatedUser();
    const r = await withServiceTx((db) =>
      db.query<{ id: string; name: string; slug: string }>(
        `select o.id, o.name, o.slug from public.organization_users ou
         join public.organizations o on o.id = ou.organization_id
         where ou.user_id = $1 and ou.status = 'active' and o.status = 'active' order by o.name`,
        [user.id],
      ),
    );
    return r.rows;
  }
}
