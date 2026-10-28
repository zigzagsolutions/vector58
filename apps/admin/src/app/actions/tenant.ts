'use server';
import {
  AddTenantUserRequestSchema,
  CreateCommandRequestSchema,
  CreateEnrollmentTokenRequestSchema,
  CreateIncidentRequestSchema,
  CreateRuleRequestSchema,
} from '@bsp/policy-types';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { getAuthorizer } from '@/server/auth';
import { parseWith } from '@/server/http';
import { setDeviceStatus } from '@/server/services/devices';
import { createEnrollmentToken, revokeEnrollmentToken } from '@/server/services/enrollment';
import { supabaseIdentityDirectory } from '@/server/services/identity';
import { createIncident, issueEndpointCommand } from '@/server/services/incidents';
import { addRule, publishPolicy, removeRule } from '@/server/services/policies';
import {
  addTenantUser,
  changeTenantUserRole,
  removeTenantUser,
} from '@/server/services/tenant-users';
import { runAction, str } from './run';
import type { ActionState } from './state';

const uuid = (v: string) => parseWith(z.uuid(), v);
const authz = () => getAuthorizer();

export async function addRuleAction(
  orgId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.policy.write');
    const input = parseWith(CreateRuleRequestSchema, {
      policyId: str(form, 'policyId'),
      ruleType: str(form, 'ruleType'),
      value: str(form, 'value'),
      category: str(form, 'category') ?? 'custom',
      priority: Number(str(form, 'priority') ?? 100),
      reason: str(form, 'reason'),
    });
    const rule = await addRule(actor, input, meta);
    revalidatePath(`/o/${orgId}`, 'layout');
    return {
      ok: true,
      message: `Added ${rule.ruleType} ${rule.normalizedValue}. Publish the policy to deliver it to endpoints.`,
    };
  });
}

export async function removeRuleAction(orgId: string, ruleId: string): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.policy.write');
    await removeRule(actor, uuid(ruleId), meta);
    revalidatePath(`/o/${orgId}`, 'layout');
    return { ok: true, message: 'Rule removed. Publish to apply.' };
  });
}

export async function publishPolicyAction(orgId: string, policyId: string): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.policy.publish');
    const r = await publishPolicy(actor, uuid(policyId), meta);
    revalidatePath(`/o/${orgId}`, 'layout');
    return {
      ok: true,
      message: `Published version ${r.versionNumber} (${r.ruleCount} rules, checksum ${r.checksum.slice(0, 12)}…)`,
    };
  });
}

export async function addUserAction(
  orgId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.users.write');
    const input = parseWith(AddTenantUserRequestSchema, {
      email: str(form, 'email'),
      roleKey: str(form, 'roleKey'),
    });
    await addTenantUser(actor, actor.organizationId, input, supabaseIdentityDirectory(), meta);
    revalidatePath(`/o/${orgId}/users`);
    return { ok: true, message: `${input.email} added` };
  });
}

export async function changeRoleAction(
  orgId: string,
  userId: string,
  roleKey: string,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.users.write');
    await changeTenantUserRole(actor, actor.organizationId, uuid(userId), roleKey, meta);
    revalidatePath(`/o/${orgId}/users`);
    return { ok: true, message: 'Role updated' };
  });
}

export async function removeUserAction(orgId: string, userId: string): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.users.write');
    await removeTenantUser(actor, actor.organizationId, uuid(userId), meta);
    revalidatePath(`/o/${orgId}/users`);
    return { ok: true, message: 'User removed' };
  });
}

export async function createEnrollmentTokenAction(
  orgId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.devices.manage');
    const input = parseWith(CreateEnrollmentTokenRequestSchema, {
      description: str(form, 'description'),
      maxUses: Number(str(form, 'maxUses') ?? 25),
      expiresInHours: Number(str(form, 'expiresInHours') ?? 72),
    });
    const t = await createEnrollmentToken(actor, input, meta);
    revalidatePath(`/o/${orgId}/settings`);
    return {
      ok: true,
      message: 'Token created. Copy it now; it will not be shown again.',
      data: { token: t.token },
    };
  });
}

export async function revokeEnrollmentTokenAction(
  orgId: string,
  tokenId: string,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.devices.manage');
    await revokeEnrollmentToken(actor, uuid(tokenId), meta);
    revalidatePath(`/o/${orgId}/settings`);
    return { ok: true };
  });
}

export async function setDeviceStatusAction(
  orgId: string,
  deviceId: string,
  status: 'active' | 'disabled',
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.devices.manage');
    await setDeviceStatus(actor, uuid(deviceId), status, meta);
    revalidatePath(`/o/${orgId}/devices`, 'layout');
    return { ok: true };
  });
}

export async function createIncidentAction(
  orgId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  let id: string | undefined;
  const res = await runAction(async (meta) => {
    const actor = await authz().requireTenantPermission(uuid(orgId), 'tenant.incident.create');
    const input = parseWith(CreateIncidentRequestSchema, {
      title: str(form, 'title'),
      description: str(form, 'description'),
      severity: str(form, 'severity'),
    });
    id = (await createIncident(actor, input, meta)).id;
    return { ok: true };
  });
  if (res.ok && id) redirect(`/o/${orgId}/incidents/${id}`);
  return res;
}

export async function issueCommandAction(
  orgId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await authz().requireTenantMembership(uuid(orgId));
    const input = parseWith(CreateCommandRequestSchema, {
      deviceId: str(form, 'deviceId'),
      commandType: str(form, 'commandType'),
      incidentId: str(form, 'incidentId'),
      payload: str(form, 'startTime')
        ? { startTime: str(form, 'startTime'), endTime: str(form, 'endTime') }
        : {},
    });
    await issueEndpointCommand(actor, input, meta);
    revalidatePath(`/o/${orgId}`, 'layout');
    return {
      ok: true,
      message: `${input.commandType} queued. The agent picks it up on its next poll.`,
    };
  });
}
