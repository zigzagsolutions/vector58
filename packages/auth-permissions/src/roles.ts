import {
  TENANT_PERMISSIONS,
  type PermissionScope,
  type PlatformPermission,
  type TenantPermission,
} from './permissions';

/**
 * Roles are named permission collections. Application code must check
 * permissions, never role keys; role keys exist for assignment and display.
 *
 * Platform roles carry two sets:
 *  - `permissions`: platform-scope permissions, effective everywhere
 *  - `tenantContextPermissions`: tenant permissions that apply ONLY while the
 *    platform user has explicitly entered a tenant context (audited). Platform
 *    users are never silently members of a tenant.
 */
export interface PlatformRoleDefinition {
  readonly key: string;
  readonly scope: 'platform';
  readonly name: string;
  readonly description: string;
  readonly permissions: readonly PlatformPermission[];
  readonly tenantContextPermissions: readonly TenantPermission[];
}

export interface TenantRoleDefinition {
  readonly key: string;
  readonly scope: 'tenant';
  readonly name: string;
  readonly description: string;
  readonly permissions: readonly TenantPermission[];
}

export type RoleDefinition = PlatformRoleDefinition | TenantRoleDefinition;

const HISTORY_EVIDENCE: readonly TenantPermission[] = [
  'tenant.incident.history.approve',
  'tenant.incident.history.read',
  'tenant.incident.history.export',
  'tenant.incident.history.delete',
];

const TENANT_READ_ONLY: readonly TenantPermission[] = [
  'tenant.users.read',
  'tenant.devices.read',
  'tenant.policy.read',
  'tenant.events.read',
  'tenant.incident.read',
  'tenant.audit.read',
  'tenant.settings.read',
];

export const PLATFORM_ROLES = {
  PlatformSuperAdmin: {
    key: 'PlatformSuperAdmin',
    scope: 'platform',
    name: 'Platform Super Admin',
    description: 'Full control of the platform and all customer tenants.',
    permissions: [
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
    ],
    // Even super admins cannot read or approve customer browser-history evidence.
    tenantContextPermissions: TENANT_PERMISSIONS.filter((p) => !HISTORY_EVIDENCE.includes(p)),
  },
  PlatformSecurityAdmin: {
    key: 'PlatformSecurityAdmin',
    scope: 'platform',
    name: 'Platform Security Admin',
    description: 'Manages global threat intelligence and assists tenants with policy.',
    permissions: [
      'platform.tenants.read',
      'platform.users.read',
      'platform.security.threats.read',
      'platform.security.threats.manage',
      'platform.security.policy.manage',
      'platform.security.incidents.read',
      'platform.audit.read',
      'platform.support.enter_tenant',
    ],
    tenantContextPermissions: [
      ...TENANT_READ_ONLY,
      'tenant.devices.manage',
      'tenant.policy.write',
      'tenant.policy.publish',
      'tenant.incident.create',
    ],
  },
  PlatformSupport: {
    key: 'PlatformSupport',
    scope: 'platform',
    name: 'Platform Support',
    description: 'Read-only troubleshooting access to tenants on request.',
    permissions: ['platform.tenants.read', 'platform.users.read', 'platform.support.enter_tenant'],
    tenantContextPermissions: [
      'tenant.users.read',
      'tenant.devices.read',
      'tenant.policy.read',
      'tenant.events.read',
      'tenant.settings.read',
    ],
  },
  PlatformAuditor: {
    key: 'PlatformAuditor',
    scope: 'platform',
    name: 'Platform Auditor',
    description: 'Reads the cross-tenant audit log. Cannot enter tenants.',
    permissions: ['platform.tenants.read', 'platform.audit.read', 'platform.security.incidents.read'],
    tenantContextPermissions: [],
  },
} as const satisfies Record<string, PlatformRoleDefinition>;

export const TENANT_ROLES = {
  TenantOwner: {
    key: 'TenantOwner',
    scope: 'tenant',
    name: 'Owner',
    description: 'Full control of the organization, including evidence access.',
    permissions: [...TENANT_PERMISSIONS],
  },
  TenantSecurityAdmin: {
    key: 'TenantSecurityAdmin',
    scope: 'tenant',
    name: 'Security Admin',
    description: 'Manages policy, devices and incidents. Can manage users up to own privilege.',
    permissions: [
      ...TENANT_READ_ONLY,
      'tenant.users.write',
      'tenant.devices.manage',
      'tenant.policy.write',
      'tenant.policy.publish',
      'tenant.incident.create',
      'tenant.incident.history.request',
    ],
  },
  TenantSecurityAnalyst: {
    key: 'TenantSecurityAnalyst',
    scope: 'tenant',
    name: 'Security Analyst',
    description: 'Investigates events and incidents. Read-only on policy.',
    permissions: [
      'tenant.devices.read',
      'tenant.policy.read',
      'tenant.events.read',
      'tenant.incident.read',
      'tenant.incident.create',
      'tenant.incident.history.request',
      'tenant.settings.read',
    ],
  },
  TenantHelpDesk: {
    key: 'TenantHelpDesk',
    scope: 'tenant',
    name: 'Help Desk',
    description: 'Checks device health and blocked events for end users.',
    permissions: ['tenant.users.read', 'tenant.devices.read', 'tenant.policy.read', 'tenant.events.read'],
  },
} as const satisfies Record<string, TenantRoleDefinition>;

export type PlatformRoleKey = keyof typeof PLATFORM_ROLES;
export type TenantRoleKey = keyof typeof TENANT_ROLES;
export type RoleKey = PlatformRoleKey | TenantRoleKey;

export const ALL_ROLES: readonly RoleDefinition[] = [
  ...Object.values(PLATFORM_ROLES),
  ...Object.values(TENANT_ROLES),
];

export const getRole = (key: string): RoleDefinition | undefined =>
  ALL_ROLES.find((r) => r.key === key);

export const rolesForScope = (scope: PermissionScope): RoleDefinition[] =>
  ALL_ROLES.filter((r) => r.scope === scope);
