import { tenantPermissionsFor } from '@bsp/auth-permissions';
import { describe, expect, it } from 'vitest';
import { PLATFORM_NAV, tenantNav, visibleNav } from './navigation';

describe('permission-driven navigation', () => {
  it('help desk sees no audit, incidents or settings', () => {
    const labels = visibleNav(tenantNav('o'), tenantPermissionsFor(['TenantHelpDesk'])).map((i) => i.label);
    expect(labels).toContain('Devices');
    expect(labels).not.toContain('Audit');
    expect(labels).not.toContain('Incidents');
  });
  it('platform nav needs platform permissions', () => {
    expect(visibleNav(PLATFORM_NAV, new Set()).map((i) => i.label)).toEqual(['Platform Dashboard', 'Settings']);
  });
});
