import 'server-only';
import type { CreateIndicatorRequest, ThreatCategory } from '@bsp/policy-types';
import { AppError, notFound } from '@bsp/shared';
import { normalizeIndicator, normalizedHash } from '@bsp/url-normalizer';
import { AuditAction, recordAudit } from '../audit';
import type { Actor, PlatformActor } from '../auth/types';
import { withServiceTx, withUserTx, type Db } from '../db';
import type { RequestMeta } from '../http';
import { processFeed, type ProcessedIndicator } from '../threat-feeds/pipeline';
import { FeedNotConfiguredError } from '../threat-feeds/provider';
import { PROVIDERS } from '../threat-feeds/providers';

const DEFAULT_TTL_DAYS = 30;

export async function listIndicators(
  actor: PlatformActor,
  filters: { q?: string; status?: string; limit?: number } = {},
) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select id, indicator_type, normalized_value, threat_category, confidence, severity, source, first_seen, last_seen,
              expires_at, status, (select count(*) from public.threat_observations o where o.indicator_id = i.id)::int as observations
       from public.threat_indicators i
       where ($1::text is null or normalized_value like '%' || lower($1) || '%') and ($2::text is null or status = $2)
       order by last_seen desc limit $3`,
      [filters.q ?? null, filters.status ?? null, filters.limit ?? 300],
    ),
  );
  return r.rows.map((i) => ({
    id: i.id as string,
    indicatorType: i.indicator_type as string,
    normalizedValue: i.normalized_value as string,
    threatCategory: i.threat_category as string,
    confidence: i.confidence as number,
    severity: i.severity as string,
    source: i.source as string,
    firstSeen: (i.first_seen as Date).toISOString(),
    lastSeen: (i.last_seen as Date).toISOString(),
    expiresAt: (i.expires_at as Date | null)?.toISOString() ?? null,
    status: i.status as string,
    observations: i.observations as number,
  }));
}

/** Upsert an indicator by normalized hash and append an observation (shared by manual entry and feeds). */
async function upsertIndicator(
  db: Db,
  sourceId: string,
  sourceName: string,
  p: ProcessedIndicator,
  ttlDays: number,
  severity = 'high',
) {
  const r = await db.query<{ id: string; inserted: boolean }>(
    `insert into public.threat_indicators (indicator_type, normalized_value, normalized_hash, hostname, threat_category,
                                           confidence, severity, source, first_seen, last_seen, expires_at, status)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $9::timestamptz + make_interval(days => $10), 'active')
     on conflict (normalized_hash) do update set
       last_seen = greatest(threat_indicators.last_seen, excluded.last_seen),
       confidence = greatest(threat_indicators.confidence, excluded.confidence),
       expires_at = greatest(threat_indicators.expires_at, excluded.expires_at),
       status = case when threat_indicators.status = 'revoked' then 'revoked' else 'active' end
     returning id, (xmax = 0) as inserted`,
    [
      p.type,
      p.value,
      p.hash,
      p.hostname,
      p.category,
      p.confidence,
      severity,
      sourceName,
      p.observedAt,
      ttlDays,
    ],
  );
  const row = r.rows[0]!;
  await db.query(
    `insert into public.threat_observations (indicator_id, source_id, observed_at, raw_value, threat_category, confidence)
     values ($1, $2, $3, $4, $5, $6)`,
    [row.id, sourceId, p.observedAt, p.raw.slice(0, 2048), p.category, p.confidence],
  );
  return row;
}

export async function createIndicator(
  actor: PlatformActor,
  input: CreateIndicatorRequest,
  request?: RequestMeta,
) {
  const n = normalizeIndicator(input.indicatorType, input.value);
  if (!n.ok)
    throw new AppError('VALIDATION_FAILED', n.error.message, {
      code: n.error.code,
      field: 'value',
    });
  const processed: ProcessedIndicator = {
    type: input.indicatorType,
    value: n.value.value,
    hash: await normalizedHash(input.indicatorType, n.value.value),
    hostname: n.value.hostname,
    category: input.threatCategory,
    confidence: input.confidence,
    raw: input.value,
    observedAt: new Date().toISOString(),
  };
  return withServiceTx(async (db) => {
    const src = await db.query<{ id: string; name: string }>(
      `select id, name from public.threat_sources where source_type = 'manual' order by created_at limit 1`,
    );
    let source = src.rows[0];
    if (!source) {
      const c = await db.query<{ id: string; name: string }>(
        `insert into public.threat_sources (name, source_type, default_confidence) values ('Manual (Platform Security)', 'manual', 95) returning id, name`,
      );
      source = c.rows[0]!;
    }
    const ttl = input.expiresAt
      ? Math.max(1, Math.ceil((Date.parse(input.expiresAt) - Date.now()) / 8.64e7))
      : 365;
    const row = await upsertIndicator(db, source.id, source.name, processed, ttl, input.severity);
    await recordAudit(db, {
      actor,
      organizationId: null,
      action: AuditAction.THREAT_INDICATOR_CREATED,
      targetType: 'threat_indicator',
      targetId: row.id,
      metadata: {
        value: processed.value,
        type: processed.type,
        category: processed.category,
        duplicate: !row.inserted,
      },
      request,
    });
    return { id: row.id, duplicate: !row.inserted, normalizedValue: processed.value };
  });
}

export async function revokeIndicator(
  actor: PlatformActor,
  indicatorId: string,
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `update public.threat_indicators set status = 'revoked' where id = $1 returning normalized_value`,
      [indicatorId],
    );
    if (!r.rowCount) throw notFound('Indicator not found');
    await recordAudit(db, {
      actor,
      organizationId: null,
      action: AuditAction.THREAT_INDICATOR_REVOKED,
      targetType: 'threat_indicator',
      targetId: indicatorId,
      metadata: { value: r.rows[0].normalized_value },
      request,
    });
  });
}

export async function listThreatSources(actor: PlatformActor) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select s.id, s.name, s.source_type, s.enabled, s.last_sync, s.sync_status, s.last_error, s.last_stats, s.default_confidence,
              (select count(distinct o.indicator_id) from public.threat_observations o where o.source_id = s.id)::int as indicators
       from public.threat_sources s order by s.name`,
    ),
  );
  return r.rows.map((s) => ({
    id: s.id as string,
    name: s.name as string,
    sourceType: s.source_type as string,
    enabled: s.enabled as boolean,
    lastSync: (s.last_sync as Date | null)?.toISOString() ?? null,
    syncStatus: s.sync_status as string,
    lastError: s.last_error as string | null,
    lastStats: s.last_stats as Record<string, number> | null,
    defaultConfidence: s.default_confidence as number,
    indicators: s.indicators as number,
  }));
}

/** Run one feed end-to-end: fetch -> validate -> normalize -> dedupe -> score -> store -> update -> expire. */
export async function syncThreatSource(actor: Actor, sourceId: string, request?: RequestMeta) {
  const src = await withServiceTx(async (db) => {
    const r = await db.query(
      `update public.threat_sources set sync_status = 'running' where id = $1 returning *`,
      [sourceId],
    );
    return r.rows[0];
  });
  if (!src) throw notFound('Threat source not found');
  const provider = PROVIDERS[src.source_type];
  try {
    if (!provider) throw new FeedNotConfiguredError(src.source_type);
    if (!src.enabled) throw new AppError('CONFLICT', 'Threat source is disabled');
    const raw = await provider.fetch({
      lastSync: src.last_sync,
      config: src.config ?? {},
      signal: AbortSignal.timeout(30_000),
    });
    return await withServiceTx(async (db) => {
      const safe = await db.query<{ normalized_value: string }>(
        `select normalized_value from public.allowlist_entries where organization_id is null and entry_type = 'domain'`,
      );
      const report = await processFeed(raw, {
        defaultCategory: provider.defaultCategory as ThreatCategory,
        defaultConfidence: src.default_confidence,
        safeDomains: safe.rows.map((s) => s.normalized_value),
      });
      let created = 0;
      let updated = 0;
      const ttl = Number(src.config?.ttlDays ?? DEFAULT_TTL_DAYS);
      for (const p of report.accepted) {
        const row = await upsertIndicator(db, src.id, src.name, p, ttl);
        if (row.inserted) created++;
        else updated++;
      }
      const expired = await expireStaleIndicators(db);
      const stats = {
        fetched: report.fetched,
        invalid: report.invalid,
        duplicates: report.duplicates,
        suppressed: report.suppressedBySafeList,
        created,
        updated,
        expired,
      };
      await db.query(
        `update public.threat_sources set sync_status = 'succeeded', last_sync = now(), last_error = null, last_stats = $2 where id = $1`,
        [src.id, JSON.stringify(stats)],
      );
      await recordAudit(db, {
        actor,
        organizationId: null,
        action: AuditAction.THREAT_FEED_SYNCED,
        targetType: 'threat_source',
        targetId: src.id,
        metadata: stats,
        request,
      });
      return stats;
    });
  } catch (e) {
    await withServiceTx((db) =>
      db.query(
        `update public.threat_sources set sync_status = 'failed', last_error = $2 where id = $1`,
        [sourceId, String((e as Error).message ?? e).slice(0, 1000)],
      ),
    );
    throw e;
  }
}

export async function expireStaleIndicators(db: Db): Promise<number> {
  const r = await db.query(
    `update public.threat_indicators set status = 'expired' where status = 'active' and expires_at <= now()`,
  );
  return r.rowCount ?? 0;
}
