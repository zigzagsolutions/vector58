import type { Permission, PlatformPermission, TenantPermission } from './permissions';
import { getRole, type RoleDefinition, type TenantRoleDefinition } from './roles';

/**
 * Pure permission evaluation over role keys. The database mirrors this logic
 * in SQL (public.has_tenant_permission / public.has_platform_permission) so
 * RLS and server-side checks agree; tests assert they stay in sync.
 */
export function platformPermissionsFor(roleKeys: readonly string[]): Set<PlatformPermission> {
  const out = new Set<PlatformPermission>();
  for (const key of roleKeys) {
    const role = getRole(key);
    if (role?.scope === 'platform') role.permissions.forEach((p) => out.add(p));
  }
  return out;
}

export function tenantPermissionsFor(roleKeys: readonly string[]): Set<TenantPermission> {
  const out = new Set<TenantPermission>();
  for (const key of roleKeys) {
    const role = getRole(key);
    if (role?.scope === 'tenant') role.permissions.forEach((p) => out.add(p));
  }
  return out;
}

/** Tenant permissions a platform user gains inside an explicitly entered tenant context. */
export function tenantContextPermissionsFor(platformRoleKeys: readonly string[]): Set<TenantPermission> {
  const out = new Set<TenantPermission>();
  for (const key of platformRoleKeys) {
    const role = getRole(key);
    if (role?.scope === 'platform') role.tenantContextPermissions.forEach((p) => out.add(p));
  }
  return out;
}

export function hasPermission(granted: ReadonlySet<Permission>, required: Permission): boolean {
  return granted.has(required);
}

/**
 * Privilege-escalation guard for role assignment: an actor may assign a role
 * only if every permission in that role is one the actor already holds.
 * This lets TenantSecurityAdmin manage analysts/help desk but never mint an
 * Owner, without hard-coding role names.
 */
export function canAssignRole(
  actorPermissions: ReadonlySet<TenantPermission>,
  role: RoleDefinition | undefined,
): role is TenantRoleDefinition {
  if (!role || role.scope !== 'tenant') return false;
  if (!actorPermissions.has('tenant.users.write')) return false;
  return role.permissions.every((p) => actorPermissions.has(p));
}
