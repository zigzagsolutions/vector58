import 'server-only';
import type {
  AgentHeartbeat,
  CommandResultRequest,
  DeviceCommand,
  DevicePolicyResponse,
  HeartbeatResponse,
  PolicyPayload,
  SecurityEventBatch,
} from '@bsp/policy-types';
import { AppError, DEVICE_OFFLINE_AFTER_SECONDS, notFound } from '@bsp/shared';
import { extractHostname, normalizeExactUrl, urlMatchesDomainRule, urlMatchesExactRule } from '@bsp/url-normalizer';
import type { DeviceActor } from '../auth/types';
import { withServiceTx, type Db } from '../db';
import { latestPublishedPayload } from './policies';

export async function recordHeartbeat(device: DeviceActor, hb: AgentHeartbeat, publicIp: string | null): Promise<HeartbeatResponse> {
  return withServiceTx(async (db) => {
    const prev = await db.query<{ last_heartbeat_at: Date | null }>(
      `select last_heartbeat_at from public.devices where id = $1 for update`,
      [device.deviceId],
    );
    await db.query(
      `update public.devices set hostname = $2, os_version = $3, agent_version = $4, local_ip = $5,
              public_ip = coalesce($6, public_ip), policy_version = $7, policy_checksum = $8, last_heartbeat_at = now()
       where id = $1`,
      [device.deviceId, hb.hostname, hb.osVersion, hb.agentVersion, hb.localIp ?? null, publicIp, hb.policyVersion,
       hb.policyChecksum ?? null],
    );
    for (const c of hb.browserClients) {
      await db.query(
        `insert into public.browser_clients (organization_id, device_id, client_id, browser, browser_version, extension_version,
                                             policy_version, native_connected, dnr_rule_count, last_seen_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
         on conflict (device_id, client_id) do update set
           browser = excluded.browser, browser_version = excluded.browser_version, extension_version = excluded.extension_version,
           policy_version = excluded.policy_version, native_connected = excluded.native_connected,
           dnr_rule_count = excluded.dnr_rule_count, last_seen_at = now()`,
        [device.organizationId, device.deviceId, c.clientId, c.browser, c.browserVersion, c.extensionVersion,
         c.policyVersion, c.nativeConnected, c.dnrRuleCount],
      );
    }
    // Record AGENT_HEARTBEAT as an event only on first contact or after an
    // offline gap, so the event store is not flooded with routine beats.
    const last = prev.rows[0]?.last_heartbeat_at;
    if (!last || Date.now() - last.getTime() > DEVICE_OFFLINE_AFTER_SECONDS * 1000) {
      await db.query(
        `insert into public.security_events (organization_id, device_id, source_event_id, event_type, occurred_at,
                                             agent_version, hostname, policy_version, details)
         values ($1, $2, gen_random_uuid(), 'AGENT_HEARTBEAT', now(), $3, $4, $5, $6)`,
        [device.organizationId, device.deviceId, hb.agentVersion, hb.hostname, hb.policyVersion,
         JSON.stringify({ resumed: Boolean(last), previousHeartbeat: last?.toISOString() ?? null })],
      );
    }
    const latest = await latestPublishedPayload(db, device.organizationId, device.policyId);
    const pending = await db.query<{ n: number }>(
      `select count(*)::int as n from public.endpoint_commands where device_id = $1 and status = 'PENDING' and expires_at > now()`,
      [device.deviceId],
    );
    return {
      serverTime: new Date().toISOString(),
      latestPolicyVersion: latest?.versionNumber ?? null,
      pendingCommands: pending.rows[0]?.n ?? 0,
    };
  });
}

/** The client's current version is only a cache hint, never an authorization input. */
export async function getDevicePolicy(device: DeviceActor, currentVersion: number | null): Promise<DevicePolicyResponse> {
  return withServiceTx(async (db) => {
    const latest = await latestPublishedPayload(db, device.organizationId, device.policyId);
    if (!latest) return { status: 'none' };
    if (currentVersion !== null && currentVersion === latest.versionNumber) {
      return { status: 'current', policyVersion: latest.versionNumber };
    }
    return { status: 'updated', policyVersion: latest.versionNumber, payload: latest.payload };
  });
}

export async function pollCommands(device: DeviceActor): Promise<DeviceCommand[]> {
  return withServiceTx(async (db) => {
    await db.query(
      `update public.endpoint_commands set status = 'EXPIRED'
       where device_id = $1 and status in ('PENDING', 'RECEIVED') and expires_at <= now()`,
      [device.deviceId],
    );
    const r = await db.query(
      `update public.endpoint_commands set status = 'RECEIVED', received_at = now()
       where id in (select id from public.endpoint_commands where device_id = $1 and organization_id = $2
                    and status = 'PENDING' order by issued_at limit 20 for update skip locked)
       returning id, command_type, payload, issued_at, expires_at`,
      [device.deviceId, device.organizationId],
    );
    return r.rows
      .sort((a, b) => a.issued_at - b.issued_at)
      .map((c) => ({
        id: c.id,
        commandType: c.command_type,
        payload: c.payload,
        issuedAt: c.issued_at.toISOString(),
        expiresAt: c.expires_at.toISOString(),
      }));
  });
}

const ALLOWED_TRANSITIONS: Record<string, string[]> = {
  RECEIVED: ['RUNNING', 'COMPLETED', 'FAILED'],
  RUNNING: ['RUNNING', 'COMPLETED', 'FAILED'],
};

const ARTIFACT_FOR: Record<string, string | undefined> = {
  COLLECT_DIAGNOSTICS: 'diagnostics',
  CHECK_EXTENSION_STATUS: 'extension_status',
  COLLECT_BROWSER_HISTORY: 'browser_history',
};

export async function submitCommandResult(device: DeviceActor, commandId: string, body: CommandResultRequest) {
  return withServiceTx(async (db) => {
    const r = await db.query(
      `select id, status, command_type, incident_id, organization_id from public.endpoint_commands
       where id = $1 and device_id = $2 for update`,
      [commandId, device.deviceId],
    );
    const cmd = r.rows[0];
    if (!cmd) throw notFound('Command not found');
    if (!ALLOWED_TRANSITIONS[cmd.status]?.includes(body.status)) {
      throw new AppError('CONFLICT', `Cannot move command from ${cmd.status} to ${body.status}`);
    }
    await db.query(
      `update public.endpoint_commands set status = $2,
              started_at = coalesce(started_at, case when $2 = 'RUNNING' then now() end),
              completed_at = case when $2 in ('COMPLETED', 'FAILED') then now() else completed_at end,
              result = coalesce($3, result), error = $4
       where id = $1`,
      [commandId, body.status, body.result ? JSON.stringify(body.result) : null, body.error ?? null],
    );
    const artifactType = ARTIFACT_FOR[cmd.command_type];
    if (body.status === 'COMPLETED' && cmd.incident_id && artifactType && body.result) {
      await db.query(
        `insert into public.incident_artifacts (organization_id, incident_id, command_id, artifact_type, content)
         values ($1, $2, $3, $4, $5)`,
        [cmd.organization_id, cmd.incident_id, commandId, artifactType, JSON.stringify(body.result)],
      );
    }
    return { id: commandId, status: body.status };
  });
}

/**
 * Event ingestion. Tenant and device come from device authentication; URL and
 * domain are re-normalised server-side; URL_BLOCKED events are cross-checked
 * against the referenced immutable policy version (category comes from the
 * policy, not the client) and flagged `verified` accordingly.
 */
export async function ingestSecurityEvents(device: DeviceActor, batch: SecurityEventBatch) {
  return withServiceTx(async (db) => {
    const payloadCache = new Map<number, PolicyPayload | null>();
    const loadPayload = async (version: number) => {
      if (!payloadCache.has(version)) {
        const r = await db.query<{ compiled_payload: PolicyPayload }>(
          `select compiled_payload from public.policy_versions where organization_id = $1 and version_number = $2
           order by published_at desc limit 1`,
          [device.organizationId, version],
        );
        payloadCache.set(version, r.rows[0]?.compiled_payload ?? null);
      }
      return payloadCache.get(version) ?? null;
    };
    const dev = await db.query<{ hostname: string; agent_version: string | null }>(
      `select hostname, agent_version from public.devices where id = $1`,
      [device.deviceId],
    );

    let accepted = 0;
    let duplicates = 0;
    for (const e of batch.events) {
      const url = e.url ? normalizeExactUrl(e.url) : null;
      const normalizedUrl = url?.ok ? url.value : null;
      const domainSource = e.domain ?? normalizedUrl;
      const domain = domainSource ? extractHostname(domainSource) : null;
      const normalizedDomain = domain?.ok ? domain.value : null;

      let category = e.threatCategory ?? null;
      const details: Record<string, unknown> = { ...(e.details ?? {}) };
      if (e.eventType === 'URL_BLOCKED') {
        const payload = e.policyVersion ? await loadPayload(e.policyVersion) : null;
        const rule = payload?.rules.find((r) => r.id === e.ruleId);
        if (rule) {
          category = rule.category;
          const target = normalizedUrl ?? (normalizedDomain ? `https://${normalizedDomain}/` : null);
          details.verified = Boolean(
            target && rule.action === 'block' &&
              (rule.type === 'domain' ? urlMatchesDomainRule(target, rule.value) : urlMatchesExactRule(target, rule.value)),
          );
          details.ruleValue = rule.value;
          details.ruleSource = rule.source;
        } else {
          details.verified = false;
        }
      }

      const r = await db.query(
        `insert into public.security_events (organization_id, device_id, source_event_id, browser_client_id, event_type,
            occurred_at, url, domain, rule_id, policy_version, threat_category, browser, browser_version,
            extension_version, agent_version, hostname, details)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         on conflict (device_id, source_event_id) do nothing`,
        [device.organizationId, device.deviceId, e.eventId, e.browserClientId ?? null, e.eventType,
         clampTime(e.occurredAt), normalizedUrl, normalizedDomain, e.ruleId ?? null, e.policyVersion ?? null, category,
         e.browser ?? null, e.browserVersion ?? null, e.extensionVersion ?? null, dev.rows[0]?.agent_version ?? null,
         dev.rows[0]?.hostname ?? null, JSON.stringify(details)],
      );
      if (r.rowCount) accepted++;
      else duplicates++;
    }
    return { accepted, duplicates };
  });
}

/** Reject wildly wrong endpoint clocks: future timestamps are clamped to now. */
function clampTime(iso: string): string {
  const t = Date.parse(iso);
  return new Date(Math.min(t, Date.now())).toISOString();
}

export type { Db };
