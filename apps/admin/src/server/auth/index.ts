import 'server-only';
import type { PlatformPermission, TenantPermission } from '@bsp/auth-permissions';
import { cache } from 'react';
import { Authorizer } from './authorizer';
import { supabaseSessionProvider } from './supabase-session';

export * from './types';
export { Authorizer } from './authorizer';

/** One Authorizer per request (React cache scopes it to the current render/request). */
export const getAuthorizer = cache(() => new Authorizer(supabaseSessionProvider));

export const requireAuthenticatedUser = () => getAuthorizer().requireAuthenticatedUser();
export const requirePlatformPermission = (p: PlatformPermission) =>
  getAuthorizer().requirePlatformPermission(p);
export const requirePlatformUser = () => getAuthorizer().requirePlatformUser();
export const requireTenantMembership = (organizationId: string) =>
  getAuthorizer().requireTenantMembership(organizationId);
export const requireTenantPermission = (organizationId: string, p: TenantPermission) =>
  getAuthorizer().requireTenantPermission(organizationId, p);
export const resolveTenantContext = () => getAuthorizer().resolveTenantContext();
