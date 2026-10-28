import 'server-only';
import type { ProtectionStatus } from '@bsp/policy-types';
import { notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { TenantActor } from '../auth/types';
import { withServiceTx, withUserTx, type Db } from '../db';
import type { RequestMeta } from '../http';
import { computeProtectionStatus } from './protection-status';

export interface BrowserClientRow {
  clientId: string;
  browser: 'chrome' | 'edge';
  browserVersion: string | null;
  extensionVersion: string | null;
  policyVersion: number | null;
  nativeConnected: boolean;
  dnrRuleCount: number | null;
  lastSeenAt: string;
}

export interface DeviceRow {
  id: string;
  hostname: string;
  osVersion: string | null;
  agentVersion: string | null;
  localIp: string | null;
  publicIp: string | null;
  status: 'active' | 'disabled';
  policyVersion: number | null;
  lastHeartbeatAt: string | null;
  enrolledAt: string;
  protection: ProtectionStatus;
  chrome: BrowserClientRow | null;
  edge: BrowserClientRow | null;
  browserClients: BrowserClientRow[];
}

async function load(db: Db, organizationId: string, deviceId?: string): Promise<DeviceRow[]> {
  const latest = await db.query<{ v: number | null; at: Date | null }>(
    `select p.current_version_number as v, pv.published_at as at
     from public.policies p left join public.policy_versions pv on pv.id = p.current_version_id
     where p.organization_id = $1 and p.is_default`,
    [organizationId],
  );
  const devices = await db.query(
    `select id, hostname, os_version, agent_version, local_ip, public_ip, status, policy_version,
            last_heartbeat_at, enrolled_at
     from public.devices where organization_id = $1 and ($2::uuid is null or id = $2::uuid)
     order by lower(hostname)`,
    [organizationId, deviceId ?? null],
  );
  const clients = await db.query(
    `select device_id, client_id, browser, browser_version, extension_version, policy_version, native_connected,
            dnr_rule_count, last_seen_at
     from public.browser_clients where organization_id = $1 and ($2::uuid is null or device_id = $2::uuid)
     order by last_seen_at desc`,
    [organizationId, deviceId ?? null],
  );
  const now = new Date();
  return devices.rows.map((d) => {
    const own = clients.rows
      .filter((c) => c.device_id === d.id)
      .map(
        (c): BrowserClientRow => ({
          clientId: c.client_id,
          browser: c.browser,
          browserVersion: c.browser_version,
          extensionVersion: c.extension_version,
          policyVersion: c.policy_version,
          nativeConnected: c.native_connected,
          dnrRuleCount: c.dnr_rule_count,
          lastSeenAt: c.last_seen_at.toISOString(),
        }),
      );
    const protection = computeProtectionStatus({
      status: d.status,
      enrolledAt: d.enrolled_at,
      lastHeartbeatAt: d.last_heartbeat_at,
      policyVersion: d.policy_version,
      latestPolicyVersion: latest.rows[0]?.v ?? null,
      latestPublishedAt: latest.rows[0]?.at ?? null,
      browserClients: own.map((c) => ({ ...c, lastSeenAt: new Date(c.lastSeenAt) })),
      now,
    });
    return {
      id: d.id,
      hostname: d.hostname,
      osVersion: d.os_version,
      agentVersion: d.agent_version,
      localIp: d.local_ip,
      publicIp: d.public_ip,
      status: d.status,
      policyVersion: d.policy_version,
      lastHeartbeatAt: d.last_heartbeat_at?.toISOString() ?? null,
      enrolledAt: d.enrolled_at.toISOString(),
      protection,
      chrome: own.find((c) => c.browser === 'chrome') ?? null,
      edge: own.find((c) => c.browser === 'edge') ?? null,
      browserClients: own,
    };
  });
}

export function listDevices(actor: TenantActor): Promise<DeviceRow[]> {
  return withUserTx(actor.user.id, (db) => load(db, actor.organizationId));
}

export async function getDevice(actor: TenantActor, deviceId: string) {
  return withUserTx(actor.user.id, async (db) => {
    const [device] = await load(db, actor.organizationId, deviceId);
    if (!device) throw notFound('Device not found');
    const events = await db.query(
      `select id, event_type, occurred_at, domain, url, policy_version, browser, threat_category
       from public.security_events where organization_id = $1 and device_id = $2 order by occurred_at desc limit 25`,
      [actor.organizationId, deviceId],
    );
    const commands = await db.query(
      `select id, command_type, status, issued_at, completed_at, error from public.endpoint_commands
       where organization_id = $1 and device_id = $2 order by issued_at desc limit 25`,
      [actor.organizationId, deviceId],
    );
    return {
      device,
      recentEvents: events.rows.map((e) => ({
        id: e.id as string,
        eventType: e.event_type as string,
        occurredAt: (e.occurred_at as Date).toISOString(),
        domain: e.domain as string | null,
        url: e.url as string | null,
        policyVersion: e.policy_version as number | null,
        browser: e.browser as string | null,
        threatCategory: e.threat_category as string | null,
      })),
      commands: commands.rows.map((c) => ({
        id: c.id as string,
        commandType: c.command_type as string,
        status: c.status as string,
        issuedAt: (c.issued_at as Date).toISOString(),
        completedAt: (c.completed_at as Date | null)?.toISOString() ?? null,
        error: c.error as string | null,
      })),
    };
  });
}

export async function setDeviceStatus(actor: TenantActor, deviceId: string, status: 'active' | 'disabled', request?: RequestMeta) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `update public.devices set status = $3,
              disabled_at = case when $3 = 'disabled' then now() else null end,
              disabled_by = case when $3 = 'disabled' then $4::uuid else null end
       where id = $1 and organization_id = $2 returning id`,
      [deviceId, actor.organizationId, status, actor.user.id],
    );
    if (!r.rowCount) throw notFound('Device not found');
    if (status === 'disabled') {
      await recordAudit(db, {
        actor, organizationId: actor.organizationId, action: AuditAction.DEVICE_DISABLED, targetType: 'device', targetId: deviceId, request,
      });
    }
  });
}
