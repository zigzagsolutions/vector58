import 'server-only';
import type { PlatformPermission, TenantPermission } from '@bsp/auth-permissions';
import { isAppError } from '@bsp/shared';
import { notFound, redirect } from 'next/navigation';
import { getAuthorizer } from './auth';
import type { PlatformActor, TenantActor } from './auth/types';

/** Map authorization failures to navigation for server-rendered pages. */
async function guard<T>(
  fn: () => Promise<T>,
  onNotFound: () => never | Promise<never>,
): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (isAppError(e)) {
      if (e.code === 'UNAUTHENTICATED') redirect('/login');
      if (e.code === 'FORBIDDEN') redirect('/denied');
      if (e.code === 'NOT_FOUND') onNotFound();
    }
    throw e;
  }
}

export async function platformPage(permission?: PlatformPermission): Promise<PlatformActor> {
  const authz = getAuthorizer();
  return guard(
    () => (permission ? authz.requirePlatformPermission(permission) : authz.requirePlatformUser()),
    () => notFound(),
  );
}

/**
 * Tenant pages. A platform user without an active context for this tenant is
 * sent to the customer page to enter it explicitly (and be audited) - never
 * silently granted access.
 */
export async function tenantPage(
  organizationId: string,
  permission?: TenantPermission,
): Promise<TenantActor> {
  const authz = getAuthorizer();
  const actor = await guard(
    () => authz.requireTenantMembership(organizationId),
    () => notFoundOrEnter(organizationId),
  );
  if (permission && !actor.permissions.has(permission)) redirect('/denied');
  return actor;
}

async function notFoundOrEnter(organizationId: string): Promise<never> {
  let isPlatform = false;
  try {
    await getAuthorizer().requirePlatformPermission('platform.support.enter_tenant');
    isPlatform = true;
  } catch {
    isPlatform = false;
  }
  if (isPlatform) redirect(`/platform/customers/${organizationId}`);
  notFound();
}

/** Helper for nullable reads behind a permission. */
export const can = (actor: TenantActor, p: TenantPermission) => actor.permissions.has(p);
