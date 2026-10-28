import { z } from 'zod';
import { BrowserSchema, IsoDateTimeSchema, UuidSchema } from './common';
import { ReportedBrowserClientSchema, ReportedSecurityEventSchema } from './api';
import { PolicyPayloadSchema } from './policy-payload';

/**
 * Messages exchanged between the browser extension and the native messaging
 * host (which relays to the Windows service). Every message is JSON framed
 * with Chromium's 32-bit little-endian length prefix.
 *
 * Host -> extension messages must stay under 1 MiB (Chromium limit).
 */
export const NATIVE_PROTOCOL_VERSION = 1;

const base = { id: z.string().max(64).optional(), protocolVersion: z.number().int().optional() };

export const PolicyUpdateMessageSchema = z.object({
  ...base,
  type: z.literal('POLICY_UPDATE'),
  policyVersion: z.number().int().positive(),
  payload: PolicyPayloadSchema,
});

export const PolicyStatusMessageSchema = z.object({
  ...base,
  type: z.literal('POLICY_STATUS'),
  policyVersion: z.number().int().nonnegative().nullable(),
  status: z.enum(['applied', 'failed', 'unchanged']),
  ruleCount: z.number().int().nonnegative(),
  error: z.string().max(2000).optional(),
  appliedAt: IsoDateTimeSchema,
});

export const RequestPolicyMessageSchema = z.object({
  ...base,
  type: z.literal('REQUEST_POLICY'),
  currentVersion: z.number().int().nonnegative().nullable(),
});

export const ClientHealthMessageSchema = z.object({
  ...base,
  type: z.literal('CLIENT_HEALTH'),
  client: ReportedBrowserClientSchema,
});

export const SecurityEventMessageSchema = z.object({
  ...base,
  type: z.literal('SECURITY_EVENT'),
  event: ReportedSecurityEventSchema,
});

export const CollectHistoryMessageSchema = z.object({
  ...base,
  type: z.literal('COLLECT_HISTORY'),
  commandId: UuidSchema,
  startTime: IsoDateTimeSchema,
  endTime: IsoDateTimeSchema,
  /** Present when this is the extension's response. Phase 1 extensions answer `unsupported`. */
  result: z
    .object({
      status: z.enum(['completed', 'unsupported', 'failed']),
      entryCount: z.number().int().nonnegative().optional(),
      error: z.string().max(2000).optional(),
    })
    .optional(),
});

export const DiagnosticRequestMessageSchema = z.object({
  ...base,
  type: z.literal('DIAGNOSTIC_REQUEST'),
  requestId: z.string().max(64),
  /** Present when this is the extension's response. */
  response: z
    .object({
      browser: BrowserSchema,
      extensionVersion: z.string(),
      policyVersion: z.number().int().nullable(),
      dnrRuleCount: z.number().int(),
      queuedEvents: z.number().int(),
      lastError: z.string().nullable(),
    })
    .optional(),
});

export const NativeMessageSchema = z.discriminatedUnion('type', [
  PolicyUpdateMessageSchema,
  PolicyStatusMessageSchema,
  RequestPolicyMessageSchema,
  ClientHealthMessageSchema,
  SecurityEventMessageSchema,
  CollectHistoryMessageSchema,
  DiagnosticRequestMessageSchema,
]);
export type NativeMessage = z.infer<typeof NativeMessageSchema>;
export type NativeMessageType = NativeMessage['type'];
export type PolicyUpdateMessage = z.infer<typeof PolicyUpdateMessageSchema>;
export type PolicyStatusMessage = z.infer<typeof PolicyStatusMessageSchema>;
export type ClientHealthMessage = z.infer<typeof ClientHealthMessageSchema>;
export type SecurityEventMessage = z.infer<typeof SecurityEventMessageSchema>;
