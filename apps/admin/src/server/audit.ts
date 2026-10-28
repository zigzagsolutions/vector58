import 'server-only';
import type { Db } from './db';
import type { Actor } from './auth/types';
import type { RequestMeta } from './http';

/**
 * Audit action catalog. Append-only; enforced by DB triggers.
 * Naming note: the spec's ROLE_ASSIGNED is recorded as TENANT_ROLE_ASSIGNED.
 */
export const AuditAction = {
  TENANT_CREATED: 'TENANT_CREATED',
  TENANT_DISABLED: 'TENANT_DISABLED',
  TENANT_ENABLED: 'TENANT_ENABLED',
  TENANT_USER_ADDED: 'TENANT_USER_ADDED',
  TENANT_USER_REMOVED: 'TENANT_USER_REMOVED',
  TENANT_ROLE_ASSIGNED: 'TENANT_ROLE_ASSIGNED',
  TENANT_ROLE_REVOKED: 'TENANT_ROLE_REVOKED',
  PLATFORM_ADMIN_ENTERED_TENANT: 'PLATFORM_ADMIN_ENTERED_TENANT',
  PLATFORM_ADMIN_EXITED_TENANT: 'PLATFORM_ADMIN_EXITED_TENANT',
  POLICY_CREATED: 'POLICY_CREATED',
  BLOCK_RULE_CREATED: 'BLOCK_RULE_CREATED',
  BLOCK_RULE_REMOVED: 'BLOCK_RULE_REMOVED',
  ALLOW_RULE_CREATED: 'ALLOW_RULE_CREATED',
  ALLOW_RULE_REMOVED: 'ALLOW_RULE_REMOVED',
  POLICY_PUBLISHED: 'POLICY_PUBLISHED',
  ENROLLMENT_TOKEN_CREATED: 'ENROLLMENT_TOKEN_CREATED',
  ENROLLMENT_TOKEN_REVOKED: 'ENROLLMENT_TOKEN_REVOKED',
  DEVICE_ENROLLED: 'DEVICE_ENROLLED',
  DEVICE_DISABLED: 'DEVICE_DISABLED',
  ENDPOINT_COMMAND_ISSUED: 'ENDPOINT_COMMAND_ISSUED',
  INCIDENT_CREATED: 'INCIDENT_CREATED',
  INCIDENT_UPDATED: 'INCIDENT_UPDATED',
  HISTORY_COLLECTION_REQUESTED: 'HISTORY_COLLECTION_REQUESTED',
  INCIDENT_EVIDENCE_VIEWED: 'INCIDENT_EVIDENCE_VIEWED',
  INCIDENT_EVIDENCE_EXPORTED: 'INCIDENT_EVIDENCE_EXPORTED',
  THREAT_INDICATOR_CREATED: 'THREAT_INDICATOR_CREATED',
  THREAT_INDICATOR_REVOKED: 'THREAT_INDICATOR_REVOKED',
  THREAT_FEED_SYNCED: 'THREAT_FEED_SYNCED',
} as const;
export type AuditActionName = (typeof AuditAction)[keyof typeof AuditAction];

export interface AuditInput {
  readonly actor: Actor;
  readonly organizationId: string | null;
  readonly action: AuditActionName;
  readonly targetType?: string;
  readonly targetId?: string | null;
  readonly metadata?: Record<string, unknown>;
  readonly request?: RequestMeta | null;
  /** Explicit tenant-context link (e.g. the entry event itself). */
  readonly tenantContextId?: string | null;
}

/** Writes an audit row in the caller's transaction, so audit and change commit atomically. */
export async function recordAudit(db: Db, input: AuditInput): Promise<void> {
  const a = input.actor;
  let actorUserId: string | null = null;
  let actorDeviceId: string | null = null;
  let scope: 'platform' | 'tenant' | 'device' | 'system' = 'system';
  let platformRole: string | null = null;
  let tenantRole: string | null = null;
  let contextId: string | null = null;

  switch (a.kind) {
    case 'platform':
      actorUserId = a.user.id;
      scope = 'platform';
      platformRole = a.platformRoles.join(',') || null;
      break;
    case 'tenant':
      actorUserId = a.user.id;
      scope = a.via === 'platform_context' ? 'platform' : 'tenant';
      platformRole = a.platformRoles.join(',') || null;
      tenantRole = a.tenantRoles.join(',') || null;
      contextId = a.contextId;
      break;
    case 'device':
      actorDeviceId = a.deviceId;
      scope = 'device';
      break;
    case 'system':
      break;
  }

  await db.query(
    `insert into public.audit_events
       (organization_id, actor_user_id, actor_email, actor_device_id, actor_scope, platform_role, tenant_role,
        tenant_context_id, action, target_type, target_id, ip_address, user_agent, metadata)
     values ($1, $2, (select email from public.profiles where id = $2), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [
      input.organizationId,
      actorUserId,
      actorDeviceId,
      scope,
      platformRole,
      tenantRole,
      input.tenantContextId ?? contextId,
      input.action,
      input.targetType ?? null,
      input.targetId ?? null,
      input.request?.ip ?? null,
      input.request?.userAgent ?? null,
      JSON.stringify(input.metadata ?? {}),
    ],
  );
}
