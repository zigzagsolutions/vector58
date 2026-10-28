import 'server-only';
import { CollectBrowserHistoryPayloadSchema, type EndpointCommandType } from '@bsp/policy-types';
import { AppError, forbidden, notFound } from '@bsp/shared';
import { AuditAction, recordAudit } from '../audit';
import type { TenantActor } from '../auth/types';
import { withServiceTx, withUserTx } from '../db';
import type { RequestMeta } from '../http';

const COMMAND_TTL_HOURS = 24;

export async function listIncidents(actor: TenantActor) {
  const r = await withUserTx(actor.user.id, (db) =>
    db.query(
      `select i.id, i.title, i.severity, i.status, i.created_at, p.email as created_by_email,
              (select count(*) from public.endpoint_commands c where c.incident_id = i.id)::int as command_count
       from public.incidents i left join public.profiles p on p.id = i.created_by
       where i.organization_id = $1 order by i.created_at desc limit 200`,
      [actor.organizationId],
    ),
  );
  return r.rows.map((i) => ({
    id: i.id as string,
    title: i.title as string,
    severity: i.severity as string,
    status: i.status as string,
    createdAt: (i.created_at as Date).toISOString(),
    createdByEmail: i.created_by_email as string | null,
    commandCount: i.command_count as number,
  }));
}

export async function createIncident(
  actor: TenantActor,
  input: { title: string; description?: string; severity: string },
  request?: RequestMeta,
) {
  return withServiceTx(async (db) => {
    const r = await db.query<{ id: string }>(
      `insert into public.incidents (organization_id, title, description, severity, created_by)
       values ($1, $2, $3, $4, $5) returning id`,
      [actor.organizationId, input.title, input.description ?? null, input.severity, actor.user.id],
    );
    const id = r.rows[0]!.id;
    await recordAudit(db, {
      actor, organizationId: actor.organizationId, action: AuditAction.INCIDENT_CREATED, targetType: 'incident', targetId: id,
      metadata: { title: input.title, severity: input.severity }, request,
    });
    return { id };
  });
}

export async function getIncident(actor: TenantActor, incidentId: string, request?: RequestMeta) {
  const data = await withUserTx(actor.user.id, async (db) => {
    const i = await db.query(
      `select i.*, p.email as created_by_email from public.incidents i left join public.profiles p on p.id = i.created_by
       where i.id = $1 and i.organization_id = $2`,
      [incidentId, actor.organizationId],
    );
    if (!i.rows[0]) throw notFound('Incident not found');
    const commands = await db.query(
      `select c.id, c.command_type, c.status, c.issued_at, c.completed_at, c.error, c.result, d.hostname
       from public.endpoint_commands c left join public.devices d on d.id = c.device_id
       where c.incident_id = $1 and c.organization_id = $2 order by c.issued_at desc`,
      [incidentId, actor.organizationId],
    );
    // RLS filters browser_history artifacts unless the actor holds tenant.incident.history.read.
    const artifacts = await db.query(
      `select id, artifact_type, command_id, content, created_at from public.incident_artifacts
       where incident_id = $1 and organization_id = $2 order by created_at desc`,
      [incidentId, actor.organizationId],
    );
    return { incident: i.rows[0], commands: commands.rows, artifacts: artifacts.rows };
  });
  if (data.artifacts.some((a) => a.artifact_type === 'browser_history')) {
    await withServiceTx((db) =>
      recordAudit(db, {
        actor, organizationId: actor.organizationId, action: AuditAction.INCIDENT_EVIDENCE_VIEWED, targetType: 'incident',
        targetId: incidentId, request,
      }),
    );
  }
  const i = data.incident;
  return {
    incident: {
      id: i.id as string,
      title: i.title as string,
      description: i.description as string | null,
      severity: i.severity as string,
      status: i.status as string,
      createdAt: (i.created_at as Date).toISOString(),
      createdByEmail: i.created_by_email as string | null,
    },
    commands: data.commands.map((c) => ({
      id: c.id as string,
      commandType: c.command_type as string,
      status: c.status as string,
      hostname: c.hostname as string | null,
      issuedAt: (c.issued_at as Date).toISOString(),
      completedAt: (c.completed_at as Date | null)?.toISOString() ?? null,
      error: c.error as string | null,
      result: c.result as Record<string, unknown> | null,
    })),
    artifacts: data.artifacts.map((a) => ({
      id: a.id as string,
      artifactType: a.artifact_type as string,
      commandId: a.command_id as string | null,
      content: a.content as unknown,
      createdAt: (a.created_at as Date).toISOString(),
    })),
  };
}

/** Required permission per command type. History needs request AND approve (two-person flow is Phase 2). */
function assertCommandPermission(actor: TenantActor, type: EndpointCommandType, incidentId: string | undefined) {
  const need = (p: Parameters<typeof actor.permissions.has>[0]) => {
    if (!actor.permissions.has(p)) throw forbidden(`Missing permission ${p}`);
  };
  if (type === 'COLLECT_BROWSER_HISTORY') {
    need('tenant.incident.history.request');
    need('tenant.incident.history.approve');
    if (!incidentId) throw new AppError('VALIDATION_FAILED', 'Browser history collection must be tied to an incident');
  } else if (incidentId) {
    need('tenant.incident.create');
  } else {
    need('tenant.devices.manage');
  }
}

export async function issueEndpointCommand(
  actor: TenantActor,
  input: { deviceId: string; commandType: EndpointCommandType; incidentId?: string; payload: Record<string, unknown> },
  request?: RequestMeta,
) {
  assertCommandPermission(actor, input.commandType, input.incidentId);
  let payload = input.payload;
  if (input.commandType === 'COLLECT_BROWSER_HISTORY') {
    payload = CollectBrowserHistoryPayloadSchema.parse({ ...input.payload, incidentId: input.incidentId, approvedBy: actor.user.id });
  } else {
    payload = {};
  }
  return withServiceTx(async (db) => {
    const d = await db.query(`select 1 from public.devices where id = $1 and organization_id = $2 and status = 'active'`, [input.deviceId, actor.organizationId]);
    if (!d.rowCount) throw notFound('Device not found');
    if (input.incidentId) {
      const i = await db.query(`select 1 from public.incidents where id = $1 and organization_id = $2`, [input.incidentId, actor.organizationId]);
      if (!i.rowCount) throw notFound('Incident not found');
    }
    const r = await db.query<{ id: string }>(
      `insert into public.endpoint_commands (organization_id, device_id, incident_id, command_type, payload, issued_by,
                                             approved_by, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(hours => $8)) returning id`,
      [actor.organizationId, input.deviceId, input.incidentId ?? null, input.commandType, JSON.stringify(payload),
       actor.user.id, input.commandType === 'COLLECT_BROWSER_HISTORY' ? actor.user.id : null, COMMAND_TTL_HOURS],
    );
    const id = r.rows[0]!.id;
    await recordAudit(db, {
      actor, organizationId: actor.organizationId,
      action: input.commandType === 'COLLECT_BROWSER_HISTORY' ? AuditAction.HISTORY_COLLECTION_REQUESTED : AuditAction.ENDPOINT_COMMAND_ISSUED,
      targetType: 'endpoint_command', targetId: id,
      metadata: { commandType: input.commandType, deviceId: input.deviceId, incidentId: input.incidentId ?? null, payload },
      request,
    });
    return { id };
  });
}

/** Export history evidence (requires tenant.incident.history.export; audited). */
export async function exportIncidentEvidence(actor: TenantActor, incidentId: string, request?: RequestMeta) {
  if (!actor.permissions.has('tenant.incident.history.export')) throw forbidden();
  const data = await getIncident(actor, incidentId, request);
  await withServiceTx((db) =>
    recordAudit(db, {
      actor, organizationId: actor.organizationId, action: AuditAction.INCIDENT_EVIDENCE_EXPORTED, targetType: 'incident',
      targetId: incidentId, metadata: { artifactCount: data.artifacts.length }, request,
    }),
  );
  return data;
}
