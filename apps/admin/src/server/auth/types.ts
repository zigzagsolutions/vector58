import type { PlatformPermission, TenantPermission } from '@bsp/auth-permissions';

export interface SessionUser {
  readonly id: string;
  readonly email: string | null;
}

/** Verifies the caller's Supabase session (cookie or bearer token). */
export interface SessionProvider {
  getUser(): Promise<SessionUser | null>;
}

export interface PlatformActor {
  readonly kind: 'platform';
  readonly user: SessionUser;
  readonly platformRoles: readonly string[];
  readonly permissions: ReadonlySet<PlatformPermission>;
}

/**
 * A user acting inside one organization. `via` records HOW access was
 * obtained: real membership, or a platform user's explicit tenant context.
 * The real identity (user.id) is always preserved - never impersonated.
 */
export interface TenantActor {
  readonly kind: 'tenant';
  readonly user: SessionUser;
  readonly organizationId: string;
  readonly organizationName: string;
  readonly permissions: ReadonlySet<TenantPermission>;
  readonly via: 'membership' | 'platform_context';
  readonly tenantRoles: readonly string[];
  readonly platformRoles: readonly string[];
  readonly contextId: string | null;
}

export interface TenantContext {
  readonly id: string;
  readonly actorUserId: string;
  readonly organizationId: string;
  readonly organizationName: string;
  readonly platformRoles: readonly string[];
  readonly startedAt: string;
  readonly expiresAt: string;
}

export interface DeviceActor {
  readonly kind: 'device';
  readonly deviceId: string;
  readonly organizationId: string;
  readonly hostname: string;
  readonly agentVersion: string | null;
  readonly policyId: string | null;
}

export type Actor = PlatformActor | TenantActor | DeviceActor | { readonly kind: 'system' };
