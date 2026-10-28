import { z } from 'zod';
import {
  BrowserSchema,
  IndicatorTypeSchema,
  IsoDateTimeSchema,
  SeveritySchema,
  SlugSchema,
  ThreatCategorySchema,
  UuidSchema,
} from './common';

/* ---------- Tenancy & identity ---------- */

export const OrganizationStatusSchema = z.enum(['active', 'disabled']);
export const OrganizationSchema = z.object({
  id: UuidSchema,
  name: z.string().min(2).max(120),
  slug: SlugSchema,
  status: OrganizationStatusSchema,
  createdAt: IsoDateTimeSchema,
  createdBy: UuidSchema.nullable(),
});
export type Organization = z.infer<typeof OrganizationSchema>;

export const UserProfileSchema = z.object({
  id: UuidSchema,
  email: z.email(),
  displayName: z.string().nullable(),
  createdAt: IsoDateTimeSchema,
});
export type UserProfile = z.infer<typeof UserProfileSchema>;

export const PermissionSchema = z.object({
  key: z.string(),
  scope: z.enum(['platform', 'tenant']),
  description: z.string(),
});
export type Permission = z.infer<typeof PermissionSchema>;

export const RoleSchema = z.object({
  key: z.string(),
  scope: z.enum(['platform', 'tenant']),
  name: z.string(),
  description: z.string(),
  permissions: z.array(z.string()),
});
export type Role = z.infer<typeof RoleSchema>;

/* ---------- Endpoints ---------- */

export const ProtectionStatusSchema = z.enum([
  'protected',
  'degraded',
  'offline',
  'never_enrolled',
  'policy_outdated',
]);
export type ProtectionStatus = z.infer<typeof ProtectionStatusSchema>;

export const DeviceStatusSchema = z.enum(['active', 'disabled']);

export const DeviceSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  hostname: z.string(),
  osVersion: z.string().nullable(),
  agentVersion: z.string().nullable(),
  localIp: z.string().nullable(),
  publicIp: z.string().nullable(),
  status: DeviceStatusSchema,
  policyVersion: z.number().int().nullable(),
  lastHeartbeatAt: IsoDateTimeSchema.nullable(),
  enrolledAt: IsoDateTimeSchema,
});
export type Device = z.infer<typeof DeviceSchema>;

export const BrowserClientSchema = z.object({
  clientId: z.string().min(8).max(64),
  browser: BrowserSchema,
  browserVersion: z.string().max(64).nullable(),
  extensionVersion: z.string().max(32).nullable(),
  policyVersion: z.number().int().nonnegative().nullable(),
  nativeConnected: z.boolean(),
  dnrRuleCount: z.number().int().nonnegative().nullable(),
  lastSeenAt: IsoDateTimeSchema,
});
export type BrowserClient = z.infer<typeof BrowserClientSchema>;

/* ---------- Threat intelligence ---------- */

export const IndicatorStatusSchema = z.enum(['active', 'expired', 'revoked']);
export const ThreatIndicatorSchema = z.object({
  id: UuidSchema,
  indicatorType: IndicatorTypeSchema,
  normalizedValue: z.string(),
  normalizedHash: z.string().length(64),
  threatCategory: ThreatCategorySchema,
  confidence: z.number().int().min(0).max(100),
  severity: SeveritySchema,
  source: z.string(),
  firstSeen: IsoDateTimeSchema,
  lastSeen: IsoDateTimeSchema,
  expiresAt: IsoDateTimeSchema.nullable(),
  status: IndicatorStatusSchema,
  createdAt: IsoDateTimeSchema,
});
export type ThreatIndicator = z.infer<typeof ThreatIndicatorSchema>;

/* ---------- Policy ---------- */

export const PolicyRuleTypeSchema = z.enum(['BLOCK_DOMAIN', 'BLOCK_URL', 'ALLOW_DOMAIN', 'ALLOW_URL']);
export type PolicyRuleType = z.infer<typeof PolicyRuleTypeSchema>;

export const PolicySchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  name: z.string().min(1).max(120),
  description: z.string().max(500).nullable(),
  isDefault: z.boolean(),
  includeGlobalThreats: z.boolean(),
  currentVersion: z.number().int().nullable(),
  createdAt: IsoDateTimeSchema,
});
export type Policy = z.infer<typeof PolicySchema>;

export const PolicyRuleSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  policyId: UuidSchema,
  ruleType: PolicyRuleTypeSchema,
  normalizedValue: z.string(),
  priority: z.number().int().min(0).max(1000),
  enabled: z.boolean(),
  category: ThreatCategorySchema,
  reason: z.string().max(500).nullable(),
  createdBy: UuidSchema.nullable(),
  createdAt: IsoDateTimeSchema,
  expiresAt: IsoDateTimeSchema.nullable(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicyVersionStatusSchema = z.enum(['published', 'superseded']);
export const PolicyVersionSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  policyId: UuidSchema,
  versionNumber: z.number().int().positive(),
  schemaVersion: z.number().int().positive(),
  ruleCount: z.number().int().nonnegative(),
  checksum: z.string().length(64),
  createdBy: UuidSchema.nullable(),
  createdAt: IsoDateTimeSchema,
  publishedAt: IsoDateTimeSchema,
  status: PolicyVersionStatusSchema,
});
export type PolicyVersion = z.infer<typeof PolicyVersionSchema>;

/* ---------- Security events ---------- */

export const SecurityEventTypeSchema = z.enum([
  'URL_BLOCKED',
  'POLICY_APPLIED',
  'POLICY_FAILED',
  'EXTENSION_CONNECTED',
  'EXTENSION_DISCONNECTED',
  'DEVICE_ENROLLED',
  'AGENT_STARTED',
  'AGENT_HEARTBEAT',
]);
export type SecurityEventType = z.infer<typeof SecurityEventTypeSchema>;

export const SecurityEventSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  deviceId: UuidSchema.nullable(),
  browserClientId: z.string().nullable(),
  eventType: SecurityEventTypeSchema,
  occurredAt: IsoDateTimeSchema,
  receivedAt: IsoDateTimeSchema,
  url: z.string().nullable(),
  domain: z.string().nullable(),
  ruleId: z.number().int().nullable(),
  policyVersion: z.number().int().nullable(),
  threatCategory: ThreatCategorySchema.nullable(),
  browser: BrowserSchema.nullable(),
  browserVersion: z.string().nullable(),
  extensionVersion: z.string().nullable(),
  agentVersion: z.string().nullable(),
  hostname: z.string().nullable(),
});
export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

/* ---------- Incident response ---------- */

export const IncidentStatusSchema = z.enum(['open', 'investigating', 'contained', 'closed']);
export const IncidentSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  title: z.string().min(3).max(200),
  description: z.string().max(5000).nullable(),
  severity: SeveritySchema,
  status: IncidentStatusSchema,
  createdBy: UuidSchema.nullable(),
  createdAt: IsoDateTimeSchema,
});
export type Incident = z.infer<typeof IncidentSchema>;

export const EndpointCommandTypeSchema = z.enum([
  'REFRESH_POLICY',
  'COLLECT_DIAGNOSTICS',
  'CHECK_EXTENSION_STATUS',
  'COLLECT_BROWSER_HISTORY',
]);
export type EndpointCommandType = z.infer<typeof EndpointCommandTypeSchema>;

export const EndpointCommandStatusSchema = z.enum([
  'PENDING',
  'RECEIVED',
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'EXPIRED',
]);
export type EndpointCommandStatus = z.infer<typeof EndpointCommandStatusSchema>;

/** Command-specific payloads. History collection is always incident-bound and time-bounded. */
export const CollectBrowserHistoryPayloadSchema = z
  .object({
    incidentId: UuidSchema,
    startTime: IsoDateTimeSchema,
    endTime: IsoDateTimeSchema,
    approvedBy: UuidSchema,
  })
  .refine((v) => Date.parse(v.endTime) > Date.parse(v.startTime), 'endTime must be after startTime')
  .refine(
    (v) => Date.parse(v.endTime) - Date.parse(v.startTime) <= 7 * 24 * 3600 * 1000,
    'History window may not exceed 7 days',
  );

export const EndpointCommandSchema = z.object({
  id: UuidSchema,
  organizationId: UuidSchema,
  deviceId: UuidSchema,
  incidentId: UuidSchema.nullable(),
  commandType: EndpointCommandTypeSchema,
  payload: z.record(z.string(), z.unknown()),
  status: EndpointCommandStatusSchema,
  issuedBy: UuidSchema.nullable(),
  issuedAt: IsoDateTimeSchema,
  expiresAt: IsoDateTimeSchema,
  completedAt: IsoDateTimeSchema.nullable(),
  result: z.record(z.string(), z.unknown()).nullable(),
});
export type EndpointCommand = z.infer<typeof EndpointCommandSchema>;
