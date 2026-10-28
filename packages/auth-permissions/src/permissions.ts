/**
 * Permission catalog. This file is the single source of truth: the database
 * seed in supabase/migrations/*_rbac_seed.sql is generated from / verified
 * against it by tests/tenant-isolation/rbac-sync.test.ts.
 */
export const PLATFORM_PERMISSIONS = [
  'platform.tenants.read',
  'platform.tenants.manage',
  'platform.users.read',
  'platform.users.manage',
  'platform.security.threats.read',
  'platform.security.threats.manage',
  'platform.security.policy.manage',
  'platform.security.incidents.read',
  'platform.audit.read',
  'platform.support.enter_tenant',
] as const;

export const TENANT_PERMISSIONS = [
  'tenant.users.read',
  'tenant.users.write',
  'tenant.devices.read',
  'tenant.devices.manage',
  'tenant.policy.read',
  'tenant.policy.write',
  'tenant.policy.publish',
  'tenant.events.read',
  'tenant.incident.read',
  'tenant.incident.create',
  'tenant.incident.history.request',
  'tenant.incident.history.approve',
  'tenant.incident.history.read',
  'tenant.incident.history.export',
  'tenant.incident.history.delete',
  'tenant.audit.read',
  'tenant.settings.read',
  'tenant.settings.write',
] as const;

export type PlatformPermission = (typeof PLATFORM_PERMISSIONS)[number];
export type TenantPermission = (typeof TENANT_PERMISSIONS)[number];
export type Permission = PlatformPermission | TenantPermission;
export type PermissionScope = 'platform' | 'tenant';

export const ALL_PERMISSIONS: readonly Permission[] = [
  ...PLATFORM_PERMISSIONS,
  ...TENANT_PERMISSIONS,
];

export const PERMISSION_DESCRIPTIONS: Readonly<Record<Permission, string>> = {
  'platform.tenants.read': 'View all customer tenants',
  'platform.tenants.manage': 'Create, disable and configure customer tenants',
  'platform.users.read': 'View platform and tenant user directories',
  'platform.users.manage': 'Manage platform users and assign tenant administrators',
  'platform.security.threats.read': 'View global threat intelligence',
  'platform.security.threats.manage': 'Manage global threat indicators and feeds',
  'platform.security.policy.manage': 'Manage platform-wide policy settings',
  'platform.security.incidents.read': 'View incidents across tenants',
  'platform.audit.read': 'View the cross-tenant audit log',
  'platform.support.enter_tenant': 'Enter a tenant context for support (audited)',
  'tenant.users.read': 'View users in the organization',
  'tenant.users.write': 'Add, remove and change roles of organization users',
  'tenant.devices.read': 'View enrolled devices',
  'tenant.devices.manage': 'Enroll, disable and command devices',
  'tenant.policy.read': 'View policies and rules',
  'tenant.policy.write': 'Create and remove block/allow rules',
  'tenant.policy.publish': 'Publish new policy versions to endpoints',
  'tenant.events.read': 'View security events',
  'tenant.incident.read': 'View incidents',
  'tenant.incident.create': 'Create incidents and issue incident commands',
  'tenant.incident.history.request': 'Request browser-history collection for an incident',
  'tenant.incident.history.approve': 'Approve browser-history collection requests',
  'tenant.incident.history.read': 'Read collected browser-history evidence',
  'tenant.incident.history.export': 'Export collected browser-history evidence',
  'tenant.incident.history.delete': 'Delete collected browser-history evidence',
  'tenant.audit.read': 'View the organization audit log',
  'tenant.settings.read': 'View organization settings',
  'tenant.settings.write': 'Change organization settings and enrollment tokens',
};

export const permissionScope = (p: Permission): PermissionScope =>
  p.startsWith('platform.') ? 'platform' : 'tenant';

export const isPermission = (value: string): value is Permission =>
  (ALL_PERMISSIONS as readonly string[]).includes(value);

export const isTenantPermission = (value: string): value is TenantPermission =>
  (TENANT_PERMISSIONS as readonly string[]).includes(value);

export const isPlatformPermission = (value: string): value is PlatformPermission =>
  (PLATFORM_PERMISSIONS as readonly string[]).includes(value);
