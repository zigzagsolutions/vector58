import 'server-only';
/**
 * Versioned product API (v1). Framework-agnostic handlers: route.ts files
 * inject real dependencies; integration tests inject fakes. Every handler
 * validates input with Zod, authorizes server-side, and derives tenancy from
 * the authenticated principal (user membership/context or device record).
 */
import {
  AddTenantUserRequestSchema,
  AgentHeartbeatSchema,
  CommandResultRequestSchema,
  CreateCommandRequestSchema,
  CreateEnrollmentTokenRequestSchema,
  CreateIncidentRequestSchema,
  CreateOrganizationRequestSchema,
  CreatePolicyRequestSchema,
  CreateRuleRequestSchema,
  EnrollmentRequestSchema,
  SecurityEventBatchSchema,
} from '@bsp/policy-types';
import { z } from 'zod';
import type { Authorizer } from '../auth/authorizer';
import { authenticateDevice } from '../device-auth';
import { assertSameOrigin, clientIp, json, parseJson, parseWith, requestMeta } from '../http';
import { listPlatformAudit, listTenantAudit } from '../services/audit-log';
import {
  getDevicePolicy,
  ingestSecurityEvents,
  pollCommands,
  recordHeartbeat,
  submitCommandResult,
} from '../services/device-api';
import { listDevices } from '../services/devices';
import { createEnrollmentToken, enrollDevice } from '../services/enrollment';
import { EventFiltersSchema, listSecurityEvents } from '../services/events';
import type { IdentityDirectory } from '../services/identity';
import { createIncident, issueEndpointCommand } from '../services/incidents';
import {
  createOrganization,
  listOrganizations,
  setOrganizationStatus,
} from '../services/organizations';
import {
  addRule,
  createPolicy,
  listPolicies,
  publishPolicy,
  removeRule,
} from '../services/policies';
import { enterTenantContext, exitTenantContext } from '../services/tenant-context';
import {
  addTenantUser,
  changeTenantUserRole,
  listTenantUsers,
  removeTenantUser,
} from '../services/tenant-users';

export interface ApiDeps {
  readonly authorizer: Authorizer;
  readonly identity: IdentityDirectory;
}

type Params<T> = { params: Promise<T> };
const Uuid = z.uuid();
const id = (v: string) => parseWith(Uuid, v);

/* ---------------- Device API ---------------- */

export async function deviceEnroll(req: Request) {
  const body = await parseJson(req, EnrollmentRequestSchema);
  return json(await enrollDevice(body, clientIp(req.headers)), { status: 201 });
}

export async function deviceHeartbeat(req: Request) {
  const device = await authenticateDevice(req);
  const body = await parseJson(req, AgentHeartbeatSchema);
  return json(await recordHeartbeat(device, body, clientIp(req.headers)));
}

export async function devicePolicy(req: Request) {
  const device = await authenticateDevice(req);
  const q = new URL(req.url).searchParams.get('currentVersion');
  const current =
    q === null || q === '' ? null : parseWith(z.coerce.number().int().nonnegative(), q);
  return json(await getDevicePolicy(device, current));
}

export async function deviceCommands(req: Request) {
  const device = await authenticateDevice(req);
  return json({ commands: await pollCommands(device) });
}

export async function deviceCommandResult(req: Request, ctx: Params<{ id: string }>) {
  const device = await authenticateDevice(req);
  const commandId = id((await ctx.params).id);
  const body = await parseJson(req, CommandResultRequestSchema);
  return json(await submitCommandResult(device, commandId, body));
}

export async function securityEvents(req: Request) {
  const device = await authenticateDevice(req);
  const body = await parseJson(req, SecurityEventBatchSchema);
  return json(await ingestSecurityEvents(device, body), { status: 202 });
}

/* ---------------- Platform API ---------------- */

export async function platformListOrganizations(_req: Request, deps: ApiDeps) {
  const actor = await deps.authorizer.requirePlatformPermission('platform.tenants.read');
  return json({ organizations: await listOrganizations(actor) });
}

export async function platformCreateOrganization(req: Request, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requirePlatformPermission('platform.tenants.manage');
  const body = await parseJson(req, CreateOrganizationRequestSchema);
  return json(
    { organization: await createOrganization(actor, body, requestMeta(req)) },
    { status: 201 },
  );
}

export async function platformSetOrganizationStatus(
  req: Request,
  ctx: Params<{ id: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requirePlatformPermission('platform.tenants.manage');
  const orgId = id((await ctx.params).id);
  const body = await parseJson(req, z.object({ status: z.enum(['active', 'disabled']) }));
  return json(await setOrganizationStatus(actor, orgId, body.status, requestMeta(req)));
}

/** Platform admin assigns a tenant administrator without entering the tenant. */
export async function platformAddTenantUser(
  req: Request,
  ctx: Params<{ id: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requirePlatformPermission('platform.users.manage');
  const orgId = id((await ctx.params).id);
  const body = await parseJson(req, AddTenantUserRequestSchema);
  return json(await addTenantUser(actor, orgId, body, deps.identity, requestMeta(req)), {
    status: 201,
  });
}

export async function platformEnterTenant(req: Request, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requirePlatformPermission('platform.support.enter_tenant');
  const body = await parseJson(
    req,
    z.object({ organizationId: Uuid, reason: z.string().trim().max(500).optional() }),
  );
  return json(
    await enterTenantContext(actor, body.organizationId, body.reason ?? null, requestMeta(req)),
    { status: 201 },
  );
}

export async function platformExitTenant(req: Request, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requirePlatformUser();
  return json(await exitTenantContext(actor, requestMeta(req)));
}

export async function platformAudit(req: Request, deps: ApiDeps) {
  const actor = await deps.authorizer.requirePlatformPermission('platform.audit.read');
  const sp = new URL(req.url).searchParams;
  const f = parseWith(
    z.object({
      organizationId: Uuid.optional(),
      action: z.string().max(64).optional(),
      limit: z.coerce.number().int().min(1).max(1000).optional(),
    }),
    Object.fromEntries(sp),
  );
  return json({ events: await listPlatformAudit(actor, f) });
}

/* ---------------- Tenant API ---------------- */

const orgParam = async (ctx: Params<{ id: string }>) => id((await ctx.params).id);

export async function orgDevices(_req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.devices.read',
  );
  return json({ devices: await listDevices(actor) });
}

export async function orgListPolicies(_req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.policy.read',
  );
  return json({ policies: await listPolicies(actor) });
}

export async function orgCreatePolicy(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.policy.write',
  );
  const body = await parseJson(req, CreatePolicyRequestSchema);
  return json(await createPolicy(actor, body, requestMeta(req)), { status: 201 });
}

export async function orgPublishPolicy(
  req: Request,
  ctx: Params<{ id: string; policyId: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const p = await ctx.params;
  const actor = await deps.authorizer.requireTenantPermission(id(p.id), 'tenant.policy.publish');
  return json(await publishPolicy(actor, id(p.policyId), requestMeta(req)), { status: 201 });
}

export async function orgCreateRule(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.policy.write',
  );
  const body = await parseJson(req, CreateRuleRequestSchema);
  return json({ rule: await addRule(actor, body, requestMeta(req)) }, { status: 201 });
}

export async function orgDeleteRule(
  req: Request,
  ctx: Params<{ id: string; ruleId: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const p = await ctx.params;
  const actor = await deps.authorizer.requireTenantPermission(id(p.id), 'tenant.policy.write');
  await removeRule(actor, id(p.ruleId), requestMeta(req));
  return new Response(null, { status: 204, headers: { 'x-api-version': 'v1' } });
}

export async function orgEvents(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.events.read',
  );
  const filters = parseWith(EventFiltersSchema, Object.fromEntries(new URL(req.url).searchParams));
  return json({ events: await listSecurityEvents(actor, filters) });
}

export async function orgAudit(_req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.audit.read',
  );
  return json({ events: await listTenantAudit(actor) });
}

export async function orgListUsers(_req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.users.read',
  );
  return json({ users: await listTenantUsers(actor) });
}

export async function orgAddUser(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  assertSameOrigin(req);
  const orgId = await orgParam(ctx);
  const actor = await deps.authorizer.requireTenantPermission(orgId, 'tenant.users.write');
  const body = await parseJson(req, AddTenantUserRequestSchema);
  return json(await addTenantUser(actor, orgId, body, deps.identity, requestMeta(req)), {
    status: 201,
  });
}

export async function orgChangeUserRole(
  req: Request,
  ctx: Params<{ id: string; userId: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const p = await ctx.params;
  const actor = await deps.authorizer.requireTenantPermission(id(p.id), 'tenant.users.write');
  const body = await parseJson(req, z.object({ roleKey: z.string().min(1).max(64) }));
  await changeTenantUserRole(
    actor,
    actor.organizationId,
    id(p.userId),
    body.roleKey,
    requestMeta(req),
  );
  return json({ ok: true });
}

export async function orgRemoveUser(
  req: Request,
  ctx: Params<{ id: string; userId: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const p = await ctx.params;
  const actor = await deps.authorizer.requireTenantPermission(id(p.id), 'tenant.users.write');
  await removeTenantUser(actor, actor.organizationId, id(p.userId), requestMeta(req));
  return new Response(null, { status: 204, headers: { 'x-api-version': 'v1' } });
}

export async function orgCreateEnrollmentToken(
  req: Request,
  ctx: Params<{ id: string }>,
  deps: ApiDeps,
) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.devices.manage',
  );
  const body = await parseJson(req, CreateEnrollmentTokenRequestSchema);
  return json(await createEnrollmentToken(actor, body, requestMeta(req)), { status: 201 });
}

export async function orgCreateIncident(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requireTenantPermission(
    await orgParam(ctx),
    'tenant.incident.create',
  );
  const body = await parseJson(req, CreateIncidentRequestSchema);
  return json(await createIncident(actor, body, requestMeta(req)), { status: 201 });
}

export async function orgCreateCommand(req: Request, ctx: Params<{ id: string }>, deps: ApiDeps) {
  assertSameOrigin(req);
  const actor = await deps.authorizer.requireTenantMembership(await orgParam(ctx));
  const body = await parseJson(req, CreateCommandRequestSchema);
  return json(await issueEndpointCommand(actor, body, requestMeta(req)), { status: 201 });
}
