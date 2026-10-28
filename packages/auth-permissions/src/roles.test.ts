import { describe, expect, it } from 'vitest';
import {
  ALL_PERMISSIONS,
  ALL_ROLES,
  PLATFORM_ROLES,
  TENANT_PERMISSIONS,
  TENANT_ROLES,
  canAssignRole,
  getRole,
  permissionScope,
  platformPermissionsFor,
  tenantContextPermissionsFor,
  tenantPermissionsFor,
} from './index';

describe('permission catalog', () => {
  it('has no duplicates and every permission is described', () => {
    expect(new Set(ALL_PERMISSIONS).size).toBe(ALL_PERMISSIONS.length);
    expect(ALL_PERMISSIONS).toHaveLength(28);
  });
  it('roles only reference permissions of their own scope', () => {
    for (const role of ALL_ROLES) {
      for (const p of role.permissions) expect(permissionScope(p)).toBe(role.scope);
      if (role.scope === 'platform') {
        for (const p of role.tenantContextPermissions) expect(permissionScope(p)).toBe('tenant');
      }
    }
  });
  it('role keys are unique', () => {
    expect(new Set(ALL_ROLES.map((r) => r.key)).size).toBe(ALL_ROLES.length);
  });
});

describe('role -> permission mapping', () => {
  it('TenantOwner has every tenant permission', () => {
    expect(tenantPermissionsFor(['TenantOwner'])).toEqual(new Set(TENANT_PERMISSIONS));
  });
  it('TenantSecurityAdmin can publish policy but cannot touch history evidence or settings', () => {
    const p = tenantPermissionsFor(['TenantSecurityAdmin']);
    expect(p.has('tenant.policy.publish')).toBe(true);
    expect(p.has('tenant.users.write')).toBe(true);
    expect(p.has('tenant.incident.history.read')).toBe(false);
    expect(p.has('tenant.incident.history.approve')).toBe(false);
    expect(p.has('tenant.settings.write')).toBe(false);
  });
  it('TenantSecurityAnalyst cannot write policy or users', () => {
    const p = tenantPermissionsFor(['TenantSecurityAnalyst']);
    expect(p.has('tenant.policy.write')).toBe(false);
    expect(p.has('tenant.policy.publish')).toBe(false);
    expect(p.has('tenant.users.write')).toBe(false);
    expect(p.has('tenant.events.read')).toBe(true);
  });
  it('TenantHelpDesk is read-only', () => {
    const p = tenantPermissionsFor(['TenantHelpDesk']);
    expect([...p].every((x) => x.endsWith('.read'))).toBe(true);
  });
  it('tenant roles grant no platform permissions', () => {
    expect(platformPermissionsFor(Object.keys(TENANT_ROLES)).size).toBe(0);
  });
  it('platform roles grant no tenant permissions outside a tenant context', () => {
    expect(tenantPermissionsFor(Object.keys(PLATFORM_ROLES)).size).toBe(0);
  });
  it('PlatformSuperAdmin context excludes history evidence', () => {
    const p = tenantContextPermissionsFor(['PlatformSuperAdmin']);
    expect(p.has('tenant.policy.publish')).toBe(true);
    expect(p.has('tenant.incident.history.read')).toBe(false);
  });
  it('PlatformSupport is read-only in tenant context; Auditor cannot enter tenants', () => {
    expect([...tenantContextPermissionsFor(['PlatformSupport'])].every((x) => x.endsWith('.read'))).toBe(true);
    expect(platformPermissionsFor(['PlatformAuditor']).has('platform.support.enter_tenant')).toBe(false);
  });
  it('unions multiple roles and ignores unknown keys', () => {
    const p = tenantPermissionsFor(['TenantHelpDesk', 'TenantSecurityAnalyst', 'Bogus']);
    expect(p.has('tenant.users.read')).toBe(true);
    expect(p.has('tenant.incident.create')).toBe(true);
  });
});

describe('canAssignRole', () => {
  const admin = tenantPermissionsFor(['TenantSecurityAdmin']);
  const owner = tenantPermissionsFor(['TenantOwner']);
  it('security admin can assign analyst/help desk/security admin but not owner', () => {
    expect(canAssignRole(admin, getRole('TenantSecurityAnalyst'))).toBe(true);
    expect(canAssignRole(admin, getRole('TenantHelpDesk'))).toBe(true);
    expect(canAssignRole(admin, getRole('TenantSecurityAdmin'))).toBe(true);
    expect(canAssignRole(admin, getRole('TenantOwner'))).toBe(false);
  });
  it('owner can assign anything tenant-scoped, never platform roles', () => {
    for (const key of Object.keys(TENANT_ROLES)) expect(canAssignRole(owner, getRole(key))).toBe(true);
    expect(canAssignRole(owner, getRole('PlatformSuperAdmin'))).toBe(false);
  });
  it('requires tenant.users.write', () => {
    expect(canAssignRole(tenantPermissionsFor(['TenantHelpDesk']), getRole('TenantHelpDesk'))).toBe(false);
  });
});
