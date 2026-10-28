import type { PlatformPermission, TenantPermission } from '@bsp/auth-permissions';

/**
 * Navigation is derived from permissions, never from role names. Hiding an
 * item is cosmetic; every page and API re-checks authorization server-side.
 */
export interface NavItem<P extends string> {
  readonly label: string;
  readonly href: string;
  readonly permission: P | null;
  readonly icon: string;
}

export const PLATFORM_NAV: readonly NavItem<PlatformPermission>[] = [
  { label: 'Platform Dashboard', href: '/platform', permission: null, icon: 'gauge' },
  {
    label: 'Customers',
    href: '/platform/customers',
    permission: 'platform.tenants.read',
    icon: 'building',
  },
  {
    label: 'Global Threats',
    href: '/platform/threats',
    permission: 'platform.security.threats.read',
    icon: 'shield',
  },
  {
    label: 'Threat Feeds',
    href: '/platform/feeds',
    permission: 'platform.security.threats.read',
    icon: 'rss',
  },
  {
    label: 'System Health',
    href: '/platform/health',
    permission: 'platform.tenants.read',
    icon: 'activity',
  },
  { label: 'Audit', href: '/platform/audit', permission: 'platform.audit.read', icon: 'scroll' },
  { label: 'Settings', href: '/platform/settings', permission: null, icon: 'settings' },
];

export const tenantNav = (orgId: string): readonly NavItem<TenantPermission>[] => [
  { label: 'Overview', href: `/o/${orgId}`, permission: null, icon: 'gauge' },
  { label: 'Users', href: `/o/${orgId}/users`, permission: 'tenant.users.read', icon: 'users' },
  {
    label: 'Devices',
    href: `/o/${orgId}/devices`,
    permission: 'tenant.devices.read',
    icon: 'monitor',
  },
  {
    label: 'Policies',
    href: `/o/${orgId}/policies`,
    permission: 'tenant.policy.read',
    icon: 'list',
  },
  {
    label: 'Allow List',
    href: `/o/${orgId}/allow-list`,
    permission: 'tenant.policy.read',
    icon: 'check',
  },
  {
    label: 'Threats',
    href: `/o/${orgId}/threats`,
    permission: 'tenant.events.read',
    icon: 'shield',
  },
  {
    label: 'Security Events',
    href: `/o/${orgId}/events`,
    permission: 'tenant.events.read',
    icon: 'zap',
  },
  {
    label: 'Incidents',
    href: `/o/${orgId}/incidents`,
    permission: 'tenant.incident.read',
    icon: 'siren',
  },
  { label: 'Audit', href: `/o/${orgId}/audit`, permission: 'tenant.audit.read', icon: 'scroll' },
  {
    label: 'Settings',
    href: `/o/${orgId}/settings`,
    permission: 'tenant.settings.read',
    icon: 'settings',
  },
];

export function visibleNav<P extends string>(
  items: readonly NavItem<P>[],
  granted: ReadonlySet<P>,
): NavItem<P>[] {
  return items.filter((i) => i.permission === null || granted.has(i.permission));
}
