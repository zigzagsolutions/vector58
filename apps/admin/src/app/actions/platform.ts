'use server';
import {
  CreateIndicatorRequestSchema,
  CreateOrganizationRequestSchema,
  AddTenantUserRequestSchema,
} from '@bsp/policy-types';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { getAuthorizer } from '@/server/auth';
import { parseWith } from '@/server/http';
import { createOrganization, setOrganizationStatus } from '@/server/services/organizations';
import { enterTenantContext, exitTenantContext } from '@/server/services/tenant-context';
import { addTenantUser } from '@/server/services/tenant-users';
import { supabaseIdentityDirectory } from '@/server/services/identity';
import { createIndicator, revokeIndicator, syncThreatSource } from '@/server/services/threats';
import { runAction, str } from './run';
import type { ActionState } from './state';

export async function createCustomerAction(
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  let id: string | undefined;
  const res = await runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission('platform.tenants.manage');
    const input = parseWith(CreateOrganizationRequestSchema, {
      name: str(form, 'name'),
      slug: str(form, 'slug'),
    });
    id = (await createOrganization(actor, input, meta)).id;
    return { ok: true };
  });
  if (res.ok && id) redirect(`/platform/customers/${id}`);
  return res;
}

export async function setCustomerStatusAction(
  organizationId: string,
  status: 'active' | 'disabled',
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission('platform.tenants.manage');
    await setOrganizationStatus(actor, parseWith(z.uuid(), organizationId), status, meta);
    revalidatePath(`/platform/customers/${organizationId}`);
    return { ok: true, message: status === 'disabled' ? 'Tenant disabled' : 'Tenant re-enabled' };
  });
}

export async function assignTenantUserAction(
  organizationId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission('platform.users.manage');
    const input = parseWith(AddTenantUserRequestSchema, {
      email: str(form, 'email'),
      roleKey: str(form, 'roleKey'),
    });
    await addTenantUser(
      actor,
      parseWith(z.uuid(), organizationId),
      input,
      supabaseIdentityDirectory(),
      meta,
    );
    revalidatePath(`/platform/customers/${organizationId}`);
    return { ok: true, message: `${input.email} added as ${input.roleKey}` };
  });
}

export async function enterTenantAction(
  organizationId: string,
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  const res = await runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission('platform.support.enter_tenant');
    await enterTenantContext(
      actor,
      parseWith(z.uuid(), organizationId),
      str(form, 'reason') ?? null,
      meta,
    );
    return { ok: true };
  });
  if (res.ok) redirect(`/o/${organizationId}`);
  return res;
}

export async function exitTenantAction(): Promise<void> {
  await runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformUser();
    await exitTenantContext(actor, meta);
    return { ok: true };
  });
  redirect('/platform');
}

export async function createIndicatorAction(
  _prev: ActionState,
  form: FormData,
): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission(
      'platform.security.threats.manage',
    );
    const input = parseWith(CreateIndicatorRequestSchema, {
      indicatorType: str(form, 'indicatorType'),
      value: str(form, 'value'),
      threatCategory: str(form, 'threatCategory'),
      confidence: Number(str(form, 'confidence') ?? 90),
      severity: str(form, 'severity') ?? 'high',
    });
    const r = await createIndicator(actor, input, meta);
    revalidatePath('/platform/threats');
    return {
      ok: true,
      message: r.duplicate
        ? `${r.normalizedValue} already existed; observation recorded`
        : `Added ${r.normalizedValue}`,
    };
  });
}

export async function revokeIndicatorAction(indicatorId: string): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission(
      'platform.security.threats.manage',
    );
    await revokeIndicator(actor, parseWith(z.uuid(), indicatorId), meta);
    revalidatePath('/platform/threats');
    return { ok: true };
  });
}

export async function syncFeedAction(sourceId: string): Promise<ActionState> {
  return runAction(async (meta) => {
    const actor = await getAuthorizer().requirePlatformPermission(
      'platform.security.threats.manage',
    );
    const stats = await syncThreatSource(actor, parseWith(z.uuid(), sourceId), meta);
    revalidatePath('/platform/feeds');
    return {
      ok: true,
      message: `Synced: ${stats.created} new, ${stats.updated} updated, ${stats.invalid} invalid, ${stats.duplicates} duplicates`,
    };
  });
}
