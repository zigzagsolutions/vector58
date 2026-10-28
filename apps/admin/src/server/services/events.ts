import 'server-only';
import { z } from 'zod';
import { SecurityEventTypeSchema, ThreatCategorySchema } from '@bsp/policy-types';
import type { TenantActor } from '../auth/types';
import { withUserTx } from '../db';

export const EventFiltersSchema = z.object({
  deviceId: z.uuid().optional(),
  hostname: z.string().trim().max(255).optional(),
  domain: z.string().trim().max(253).optional(),
  category: ThreatCategorySchema.optional(),
  eventType: SecurityEventTypeSchema.optional(),
  policyVersion: z.coerce.number().int().nonnegative().optional(),
  from: z.iso.datetime({ offset: true }).optional(),
  to: z.iso.datetime({ offset: true }).optional(),
  range: z.enum(['1h', '24h', '7d', '30d']).optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});
export type EventFilters = z.infer<typeof EventFiltersSchema>;

const RANGE_MS: Record<string, number> = {
  '1h': 3.6e6,
  '24h': 8.64e7,
  '7d': 6.048e8,
  '30d': 2.592e9,
};

export interface SecurityEventRow {
  id: string;
  eventType: string;
  occurredAt: string;
  receivedAt: string;
  deviceId: string | null;
  hostname: string | null;
  url: string | null;
  domain: string | null;
  ruleId: number | null;
  policyVersion: number | null;
  threatCategory: string | null;
  browser: string | null;
  browserVersion: string | null;
  extensionVersion: string | null;
  agentVersion: string | null;
  verified: boolean | null;
}

/** Tenant event search. Runs under RLS; organization comes from the authorized actor. */
export async function listSecurityEvents(
  actor: TenantActor,
  filters: EventFilters,
): Promise<SecurityEventRow[]> {
  const where: string[] = ['organization_id = $1'];
  const params: unknown[] = [actor.organizationId];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace('?', `$${params.length}`));
  };
  if (filters.deviceId) add('device_id = ?', filters.deviceId);
  if (filters.hostname) add('lower(hostname) like ?', `%${filters.hostname.toLowerCase()}%`);
  if (filters.domain) add('domain like ?', `%${filters.domain.toLowerCase()}%`);
  if (filters.category) add('threat_category = ?', filters.category);
  if (filters.eventType) add('event_type = ?', filters.eventType);
  if (filters.policyVersion !== undefined) add('policy_version = ?', filters.policyVersion);
  const from =
    filters.from ??
    (filters.range ? new Date(Date.now() - RANGE_MS[filters.range]!).toISOString() : undefined);
  if (from) add('occurred_at >= ?', from);
  if (filters.to) add('occurred_at <= ?', filters.to);
  params.push(filters.limit);

  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select id, event_type, occurred_at, received_at, device_id, hostname, url, domain, rule_id, policy_version,
              threat_category, browser, browser_version, extension_version, agent_version, details
       from public.security_events where ${where.join(' and ')}
       order by occurred_at desc limit $${params.length}`,
      params,
    ),
  );
  return r.rows.map((e) => ({
    id: e.id,
    eventType: e.event_type,
    occurredAt: e.occurred_at.toISOString(),
    receivedAt: e.received_at.toISOString(),
    deviceId: e.device_id,
    hostname: e.hostname,
    url: e.url,
    domain: e.domain,
    ruleId: e.rule_id,
    policyVersion: e.policy_version,
    threatCategory: e.threat_category,
    browser: e.browser,
    browserVersion: e.browser_version,
    extensionVersion: e.extension_version,
    agentVersion: e.agent_version,
    verified: typeof e.details?.verified === 'boolean' ? e.details.verified : null,
  }));
}

/** Tenant "Threats" view: blocked destinations aggregated by domain and category. */
export async function blockedThreatSummary(actor: TenantActor, days = 30) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select domain, threat_category, count(*)::int as hits, count(distinct device_id)::int as devices,
              max(occurred_at) as last_seen
       from public.security_events
       where organization_id = $1 and event_type = 'URL_BLOCKED' and occurred_at > now() - make_interval(days => $2)
       group by domain, threat_category order by hits desc limit 200`,
      [actor.organizationId, days],
    ),
  );
  return r.rows.map((x) => ({
    domain: x.domain as string | null,
    category: x.threat_category as string | null,
    hits: x.hits as number,
    devices: x.devices as number,
    lastSeen: (x.last_seen as Date).toISOString(),
  }));
}
