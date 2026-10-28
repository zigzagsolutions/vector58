import { z } from 'zod';
import { IndicatorTypeSchema, IsoDateTimeSchema, ThreatCategorySchema, UuidSchema } from './common';

/** Max rule id. DNR rule ids are derived as ruleId*2 and ruleId*2+1 and must stay < 2^31. */
export const MAX_POLICY_RULE_ID = 2 ** 29;

export const CompiledRuleSchema = z.object({
  id: z.number().int().min(1).max(MAX_POLICY_RULE_ID),
  type: IndicatorTypeSchema,
  value: z.string().min(1).max(2048),
  action: z.enum(['block', 'allow']),
  category: ThreatCategorySchema,
  priority: z.number().int().min(1).max(10_000),
  source: z.enum(['tenant', 'global']),
});
export type CompiledRule = z.infer<typeof CompiledRuleSchema>;

export const PolicyPayloadSchema = z
  .object({
    schemaVersion: z.literal(1),
    policyVersion: z.number().int().positive(),
    organizationId: UuidSchema,
    generatedAt: IsoDateTimeSchema,
    checksum: z.string().regex(/^[0-9a-f]{64}$/),
    /** Reserved for detached policy signatures (Phase 2). Not covered by checksum. */
    signature: z.string().optional(),
    rules: z.array(CompiledRuleSchema).max(30_000),
  })
  .refine((p) => new Set(p.rules.map((r) => r.id)).size === p.rules.length, {
    message: 'Rule ids must be unique',
    path: ['rules'],
  });
export type PolicyPayload = z.infer<typeof PolicyPayloadSchema>;
