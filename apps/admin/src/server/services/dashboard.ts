import 'server-only';
import type { PlatformActor, TenantActor } from '../auth/types';
import { withServiceTx, withUserTx } from '../db';
import { listDevices } from './devices';

export async function tenantDashboard(actor: TenantActor) {
  const canDevices = actor.permissions.has('tenant.devices.read');
  const devices = canDevices ? await listDevices(actor) : [];
  const stats = await withUserTx(actor.user.id, async (db) => {
    const q = async (sql: string) => (await db.query(sql, [actor.organizationId])).rows[0];
    return {
      blockedToday: actor.permissions.has('tenant.events.read')
        ? ((
            await q(`select count(*)::int as n from public.security_events where organization_id = $1
                    and event_type = 'URL_BLOCKED' and occurred_at >= date_trunc('day', now())`)
          )?.n ?? 0)
        : null,
      policies: actor.permissions.has('tenant.policy.read')
        ? await q(`select count(*)::int as n, max(current_version_number) as latest from public.policies
                   where organization_id = $1 and status = 'active'`)
        : null,
      openIncidents: actor.permissions.has('tenant.incident.read')
        ? ((
            await q(
              `select count(*)::int as n from public.incidents where organization_id = $1 and status <> 'closed'`,
            )
          )?.n ?? 0)
        : null,
      recent: actor.permissions.has('tenant.events.read')
        ? (
            await db.query(
              `select id, occurred_at, hostname, domain, threat_category, browser from public.security_events
             where organization_id = $1 and event_type = 'URL_BLOCKED' order by occurred_at desc limit 10`,
              [actor.organizationId],
            )
          ).rows
        : [],
    };
  });
  return {
    activeDevices: canDevices
      ? devices.filter((d) => d.status === 'active' && d.protection !== 'offline').length
      : null,
    protectedDevices: canDevices
      ? devices.filter((d) => d.protection === 'protected').length
      : null,
    outdatedDevices: canDevices
      ? devices.filter((d) => d.protection === 'policy_outdated').length
      : null,
    totalDevices: canDevices ? devices.length : null,
    blockedToday: stats.blockedToday,
    activePolicies: stats.policies?.n ?? null,
    latestPolicyVersion: stats.policies?.latest ?? null,
    openIncidents: stats.openIncidents,
    recentThreatEvents: stats.recent.map((e) => ({
      id: e.id as string,
      occurredAt: (e.occurred_at as Date).toISOString(),
      hostname: e.hostname as string | null,
      domain: e.domain as string | null,
      category: e.threat_category as string | null,
      browser: e.browser as string | null,
    })),
  };
}

/** Platform-wide aggregates. Counts only; no tenant row data leaves this function. */
export async function platformDashboard(actor: PlatformActor) {
  void actor;
  return withServiceTx(async (db) => {
    const one = async (sql: string) => (await db.query(sql)).rows[0];
    const tenants = await one(
      `select count(*) filter (where status = 'active')::int as active, count(*)::int as total from public.organizations`,
    );
    const devices = await one(`select count(*)::int as total,
                                      count(*) filter (where last_heartbeat_at > now() - interval '5 minutes')::int as online
                               from public.devices where status = 'active'`);
    const blocked = await one(`select count(*)::int as n from public.security_events
                               where event_type = 'URL_BLOCKED' and occurred_at >= date_trunc('day', now())`);
    const indicators = await one(
      `select count(*)::int as n from public.threat_indicators where status = 'active'`,
    );
    const feeds = (
      await db.query(
        `select name, source_type, enabled, last_sync, sync_status from public.threat_sources order by name`,
      )
    ).rows;
    const agents = (
      await db.query(`select coalesce(agent_version, 'unknown') as version, count(*)::int as n from public.devices
                                    where status = 'active' group by 1 order by 2 desc`)
    ).rows;
    return {
      activeTenants: tenants?.active ?? 0,
      totalTenants: tenants?.total ?? 0,
      totalDevices: devices?.total ?? 0,
      onlineDevices: devices?.online ?? 0,
      blockedToday: blocked?.n ?? 0,
      activeIndicators: indicators?.n ?? 0,
      feeds: feeds.map((f) => ({
        name: f.name as string,
        sourceType: f.source_type as string,
        enabled: f.enabled as boolean,
        lastSync: (f.last_sync as Date | null)?.toISOString() ?? null,
        syncStatus: f.sync_status as string,
      })),
      agentVersions: agents.map((a) => ({ version: a.version as string, count: a.n as number })),
    };
  });
}

export async function systemHealth() {
  const started = Date.now();
  try {
    await withServiceTx((db) => db.query('select 1'));
    return { database: 'ok' as const, latencyMs: Date.now() - started };
  } catch (e) {
    return { database: 'error' as const, latencyMs: Date.now() - started, error: String(e) };
  }
}
