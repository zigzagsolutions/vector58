import 'server-only';
import { compilePolicy, type GlobalIndicatorInput, type TenantRuleInput } from '@bsp/policy-engine';
import type {
  CreatePolicyRequest,
  CreateRuleRequest,
  PolicyPayload,
  PolicyRuleType,
} from '@bsp/policy-types';
import { AppError, conflict, notFound } from '@bsp/shared';
import { hostnameMatchesDomain, normalizeIndicator, normalizedHash } from '@bsp/url-normalizer';
import { AuditAction, recordAudit } from '../audit';
import type { TenantActor } from '../auth/types';
import { withServiceTx, withUserTx, type Db } from '../db';
import type { RequestMeta } from '../http';

export interface PolicySummary {
  id: string;
  name: string;
  description: string | null;
  isDefault: boolean;
  includeGlobalThreats: boolean;
  currentVersion: number | null;
  ruleCount: number;
  updatedAt: string;
}

export interface RuleRow {
  id: string;
  policyId: string;
  ruleType: PolicyRuleType;
  normalizedValue: string;
  priority: number;
  enabled: boolean;
  category: string;
  reason: string | null;
  createdBy: string | null;
  createdByEmail: string | null;
  createdAt: string;
  expiresAt: string | null;
}

export interface VersionRow {
  id: string;
  versionNumber: number;
  schemaVersion: number;
  ruleCount: number;
  checksum: string;
  status: string;
  createdBy: string | null;
  createdByEmail: string | null;
  publishedAt: string;
}

export async function listPolicies(actor: TenantActor): Promise<PolicySummary[]> {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select p.id, p.name, p.description, p.is_default, p.include_global_threats, p.current_version_number, p.updated_at,
              (select count(*) from public.policy_rules r where r.policy_id = p.id and r.deleted_at is null)::int as rule_count
       from public.policies p where p.organization_id = $1 and p.status = 'active'
       order by p.is_default desc, p.name`,
      [actor.organizationId],
    ),
  );
  return r.rows.map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
    isDefault: p.is_default,
    includeGlobalThreats: p.include_global_threats,
    currentVersion: p.current_version_number,
    ruleCount: p.rule_count,
    updatedAt: p.updated_at.toISOString(),
  }));
}

export async function getPolicyDetail(actor: TenantActor, policyId: string) {
  return withUserTx(actor.user.id, async (db) => {
    const p = await db.query(
      `select id, name, description, is_default, include_global_threats, min_global_confidence, current_version_number, updated_at
       from public.policies where id = $1 and organization_id = $2`,
      [policyId, actor.organizationId],
    );
    const policy = p.rows[0];
    if (!policy) throw notFound('Policy not found');
    const rules = await db.query(
      `select r.*, pr.email as created_by_email from public.policy_rules r
       left join public.profiles pr on pr.id = r.created_by
       where r.policy_id = $1 and r.organization_id = $2 and r.deleted_at is null
       order by r.rule_type, r.normalized_value`,
      [policyId, actor.organizationId],
    );
    const versions = await db.query(
      `select v.id, v.version_number, v.schema_version, v.rule_count, v.checksum, v.status, v.created_by, v.published_at,
              pr.email as created_by_email
       from public.policy_versions v left join public.profiles pr on pr.id = v.created_by
       where v.policy_id = $1 and v.organization_id = $2 order by v.version_number desc limit 50`,
      [policyId, actor.organizationId],
    );
    return {
      policy: {
        id: policy.id as string,
        name: policy.name as string,
        description: policy.description as string | null,
        isDefault: policy.is_default as boolean,
        includeGlobalThreats: policy.include_global_threats as boolean,
        minGlobalConfidence: policy.min_global_confidence as number,
        currentVersion: policy.current_version_number as number | null,
      },
      rules: rules.rows.map(mapRule),
      versions: versions.rows.map((v): VersionRow => ({
        id: v.id,
        versionNumber: v.version_number,
        schemaVersion: v.schema_version,
        ruleCount: v.rule_count,
        checksum: v.checksum,
        status: v.status,
        createdBy: v.created_by,
        createdByEmail: v.created_by_email,
        publishedAt: v.published_at.toISOString(),
      })),
    };
  });
}

function mapRule(r: Record<string, unknown>): RuleRow {
  return {
    id: r.id as string,
    policyId: r.policy_id as string,
    ruleType: r.rule_type as PolicyRuleType,
    normalizedValue: r.normalized_value as string,
    priority: r.priority as number,
    enabled: r.enabled as boolean,
    category: r.category as string,
    reason: (r.reason as string | null) ?? null,
    createdBy: (r.created_by as string | null) ?? null,
    createdByEmail: (r.created_by_email as string | null) ?? null,
    createdAt: (r.created_at as Date).toISOString(),
    expiresAt: (r.expires_at as Date | null)?.toISOString() ?? null,
  };
}

export async function createPolicy(
  actor: TenantActor,
  input: CreatePolicyRequest,
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const r = await db.query<{ id: string }>(
      `insert into public.policies (organization_id, name, description, include_global_threats, created_by)
       values ($1, $2, $3, $4, $5) returning id`,
      [
        actor.organizationId,
        input.name,
        input.description ?? null,
        input.includeGlobalThreats,
        actor.user.id,
      ],
    );
    const id = r.rows[0]!.id;
    await recordAudit(db, {
      actor,
      organizationId: actor.organizationId,
      action: AuditAction.POLICY_CREATED,
      targetType: 'policy',
      targetId: id,
      metadata: { name: input.name },
      request,
    });
    return { id };
  });
}

async function defaultPolicyId(db: Db, organizationId: string): Promise<string> {
  const r = await db.query<{ id: string }>(
    `select id from public.policies where organization_id = $1 and is_default and status = 'active'`,
    [organizationId],
  );
  if (!r.rows[0]) throw notFound('Organization has no default policy');
  return r.rows[0].id;
}

const RULE_KIND: Record<PolicyRuleType, 'domain' | 'exact_url'> = {
  BLOCK_DOMAIN: 'domain',
  ALLOW_DOMAIN: 'domain',
  BLOCK_URL: 'exact_url',
  ALLOW_URL: 'exact_url',
};

/** Add a block/allow entry. Input is normalised with the shared URL normaliser; duplicates are rejected. */
export async function addRule(actor: TenantActor, input: CreateRuleRequest, request?: RequestMeta) {
  const kind = RULE_KIND[input.ruleType];
  const normalized = normalizeIndicator(kind, input.value);
  if (!normalized.ok) {
    throw new AppError('VALIDATION_FAILED', normalized.error.message, {
      code: normalized.error.code,
      field: 'value',
    });
  }
  const value = normalized.value.value;
  const hash = await normalizedHash(kind, value);
  if (input.expiresAt && Date.parse(input.expiresAt) <= Date.now()) {
    throw new AppError('VALIDATION_FAILED', 'expiresAt must be in the future');
  }

  return withServiceTx(async (db) => {
    const policyId = input.policyId ?? (await defaultPolicyId(db, actor.organizationId));
    const p = await db.query(
      `select 1 from public.policies where id = $1 and organization_id = $2`,
      [policyId, actor.organizationId],
    );
    if (!p.rowCount) throw notFound('Policy not found');
    const dup = await db.query(
      `select id from public.policy_rules
       where policy_id = $1 and rule_type = $2 and normalized_hash = $3 and deleted_at is null`,
      [policyId, input.ruleType, hash],
    );
    if (dup.rowCount) throw conflict(`"${value}" is already in this policy as ${input.ruleType}`);

    const r = await db.query(
      `insert into public.policy_rules (organization_id, policy_id, rule_type, normalized_value, normalized_hash,
                                        priority, category, reason, created_by, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning *`,
      [
        actor.organizationId,
        policyId,
        input.ruleType,
        value,
        hash,
        input.priority,
        input.category,
        input.reason ?? null,
        actor.user.id,
        input.expiresAt ?? null,
      ],
    );
    const rule = mapRule(r.rows[0]);
    await recordAudit(db, {
      actor,
      organizationId: actor.organizationId,
      action: input.ruleType.startsWith('BLOCK')
        ? AuditAction.BLOCK_RULE_CREATED
        : AuditAction.ALLOW_RULE_CREATED,
      targetType: 'policy_rule',
      targetId: rule.id,
      metadata: {
        policyId,
        ruleType: input.ruleType,
        value,
        input: input.value,
        category: input.category,
      },
      request,
    });
    return rule;
  });
}

/** Soft-delete a rule. Historical policy versions keep their compiled copy. */
export async function removeRule(actor: TenantActor, ruleId: string, request?: RequestMeta) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `update public.policy_rules set deleted_at = now(), deleted_by = $3
       where id = $1 and organization_id = $2 and deleted_at is null returning rule_type, normalized_value, policy_id`,
      [ruleId, actor.organizationId, actor.user.id],
    );
    const row = r.rows[0];
    // A rule id from another tenant behaves exactly like a missing one.
    if (!row) throw notFound('Rule not found');
    await recordAudit(db, {
      actor,
      organizationId: actor.organizationId,
      action: String(row.rule_type).startsWith('BLOCK')
        ? AuditAction.BLOCK_RULE_REMOVED
        : AuditAction.ALLOW_RULE_REMOVED,
      targetType: 'policy_rule',
      targetId: ruleId,
      metadata: { policyId: row.policy_id, ruleType: row.rule_type, value: row.normalized_value },
      request,
    });
  });
}

/** Active global indicators minus the platform-wide safe list. */
async function loadGlobalIndicators(
  db: Db,
  minConfidence: number,
): Promise<GlobalIndicatorInput[]> {
  const indicators = await db.query(
    `select indicator_type, normalized_value, threat_category, confidence, status, expires_at
     from public.threat_indicators where status = 'active' and confidence >= $1
       and (expires_at is null or expires_at > now())`,
    [minConfidence],
  );
  const allow = await db.query<{ entry_type: string; normalized_value: string }>(
    `select entry_type, normalized_value from public.allowlist_entries where organization_id is null`,
  );
  const safeDomains = allow.rows
    .filter((a) => a.entry_type === 'domain')
    .map((a) => a.normalized_value);
  const safeUrls = new Set(
    allow.rows.filter((a) => a.entry_type === 'exact_url').map((a) => a.normalized_value),
  );
  return indicators.rows
    .filter((i) => {
      if (i.indicator_type === 'exact_url' && safeUrls.has(i.normalized_value)) return false;
      const host =
        i.indicator_type === 'domain' ? i.normalized_value : new URL(i.normalized_value).hostname;
      return !safeDomains.some((d) => hostnameMatchesDomain(host, d));
    })
    .map((i) => ({
      indicatorType: i.indicator_type,
      normalizedValue: i.normalized_value,
      threatCategory: i.threat_category,
      confidence: i.confidence,
      status: i.status,
      expiresAt: i.expires_at?.toISOString() ?? null,
    }));
}

/**
 * Publish: compile global intel + tenant rules into a new immutable
 * policy_versions row. The policy row is locked so concurrent publishes
 * serialise; the (policy_id, version_number) unique key is a second guard.
 */
export async function publishPolicy(actor: TenantActor, policyId: string, request?: RequestMeta) {
  return withServiceTx(async (db) => {
    const p = await db.query(
      `select id, include_global_threats, min_global_confidence, current_version_id
       from public.policies where id = $1 and organization_id = $2 and status = 'active' for update`,
      [policyId, actor.organizationId],
    );
    const policy = p.rows[0];
    if (!policy) throw notFound('Policy not found');

    const max = await db.query<{ v: number | null }>(
      `select max(version_number) as v from public.policy_versions where policy_id = $1`,
      [policyId],
    );
    const versionNumber = (max.rows[0]?.v ?? 0) + 1;

    const rules = await db.query(
      `select rule_type, normalized_value, priority, enabled, category, expires_at
       from public.policy_rules where policy_id = $1 and organization_id = $2 and deleted_at is null`,
      [policyId, actor.organizationId],
    );
    const tenantRules: TenantRuleInput[] = rules.rows.map((r) => ({
      ruleType: r.rule_type,
      normalizedValue: r.normalized_value,
      priority: r.priority,
      enabled: r.enabled,
      category: r.category,
      expiresAt: r.expires_at?.toISOString() ?? null,
    }));
    const globalIndicators = policy.include_global_threats
      ? await loadGlobalIndicators(db, policy.min_global_confidence)
      : [];

    const { payload, stats } = await compilePolicy({
      organizationId: actor.organizationId,
      policyVersion: versionNumber,
      generatedAt: new Date().toISOString(),
      tenantRules,
      globalIndicators,
      config: {
        includeGlobalThreats: policy.include_global_threats,
        minGlobalConfidence: policy.min_global_confidence,
      },
    });

    const v = await db.query<{ id: string; published_at: Date }>(
      `insert into public.policy_versions (organization_id, policy_id, version_number, schema_version, rule_count,
                                           checksum, compiled_payload, compiler_stats, created_by)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9) returning id, published_at`,
      [
        actor.organizationId,
        policyId,
        versionNumber,
        payload.schemaVersion,
        payload.rules.length,
        payload.checksum,
        JSON.stringify(payload),
        JSON.stringify(stats),
        actor.user.id,
      ],
    );
    const versionId = v.rows[0]!.id;
    await db.query(
      `update public.policy_versions set status = 'superseded'
       where policy_id = $1 and status = 'published' and id <> $2`,
      [policyId, versionId],
    );
    await db.query(
      `update public.policies set current_version_number = $2, current_version_id = $3 where id = $1`,
      [policyId, versionNumber, versionId],
    );
    await recordAudit(db, {
      actor,
      organizationId: actor.organizationId,
      action: AuditAction.POLICY_PUBLISHED,
      targetType: 'policy_version',
      targetId: versionId,
      metadata: {
        policyId,
        versionNumber,
        checksum: payload.checksum,
        ruleCount: payload.rules.length,
        stats,
      },
      request,
    });
    return {
      versionId,
      policyId,
      versionNumber,
      checksum: payload.checksum,
      ruleCount: payload.rules.length,
      stats,
      publishedAt: v.rows[0]!.published_at.toISOString(),
    };
  });
}

/** Latest published payload for a device's policy (device API; service connection). */
export async function latestPublishedPayload(
  db: Db,
  organizationId: string,
  policyId: string | null,
): Promise<{ versionNumber: number; payload: PolicyPayload } | null> {
  const r = await db.query<{ version_number: number; compiled_payload: PolicyPayload }>(
    `select v.version_number, v.compiled_payload
     from public.policies p join public.policy_versions v on v.id = p.current_version_id
     where p.organization_id = $1 and p.status = 'active'
       and (case when $2::uuid is null then p.is_default else p.id = $2::uuid end)`,
    [organizationId, policyId],
  );
  const row = r.rows[0];
  return row ? { versionNumber: row.version_number, payload: row.compiled_payload } : null;
}
