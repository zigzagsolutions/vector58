-- =============================================================================
-- Row Level Security.
--
-- Model:
--  * RLS is enabled on EVERY table in public.
--  * anon has no access to anything.
--  * authenticated gets SELECT only, filtered by permission-aware policies.
--  * All writes go through trusted server-side APIs (apps/admin/src/server)
--    which run their own authorization checks and write audit records. The
--    service credential is server-only and never shipped to browsers.
-- =============================================================================

do $$
declare t text;
begin
  for t in select tablename from pg_tables where schemaname = 'public' loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select on public.%I to authenticated', t);
  end loop;
end;
$$;

-- Tables created by future migrations must not silently become readable.
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on functions from anon;

-- ---------- Reference data ----------
create policy permissions_read on public.permissions for select to authenticated using (true);
create policy roles_read on public.roles for select to authenticated
  using (organization_id is null or organization_id in (select public.permitted_organization_ids('tenant.users.read')));
create policy role_permissions_read on public.role_permissions for select to authenticated using (true);
create policy agent_releases_read on public.agent_releases for select to authenticated using (status = 'released');
create policy extension_releases_read on public.extension_releases for select to authenticated using (status = 'released');

-- ---------- Identity ----------
create policy profiles_read on public.profiles for select to authenticated
  using (
    id = auth.uid()
    or public.has_platform_permission('platform.users.read')
    or exists (
      select 1 from public.organization_users ou
      where ou.user_id = profiles.id
        and ou.organization_id in (select public.permitted_organization_ids('tenant.users.read'))
    )
  );

create policy organizations_read on public.organizations for select to authenticated
  using (id in (select public.visible_organization_ids()));

create policy organization_users_read on public.organization_users for select to authenticated
  using (
    user_id = auth.uid()
    or organization_id in (select public.permitted_organization_ids('tenant.users.read'))
    or public.has_platform_permission('platform.users.read')
  );

create policy organization_user_roles_read on public.organization_user_roles for select to authenticated
  using (
    user_id = auth.uid()
    or organization_id in (select public.permitted_organization_ids('tenant.users.read'))
    or public.has_platform_permission('platform.users.read')
  );

create policy platform_user_roles_read on public.platform_user_roles for select to authenticated
  using (user_id = auth.uid() or public.has_platform_permission('platform.users.read'));

create policy platform_tenant_contexts_read on public.platform_tenant_contexts for select to authenticated
  using (actor_user_id = auth.uid() or public.has_platform_permission('platform.audit.read'));

create policy enrollment_tokens_read on public.enrollment_tokens for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.settings.read')));

-- ---------- Endpoints ----------
create policy devices_read on public.devices for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.devices.read')));
create policy browser_clients_read on public.browser_clients for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.devices.read')));

-- devices.credential_hash is never needed client-side.
revoke select on public.devices from authenticated;
grant select (
  id, organization_id, installation_id, hostname, os_version, agent_version, local_ip, public_ip,
  machine, status, policy_id, policy_version, policy_checksum, enrolled_at, enrollment_token_id,
  last_heartbeat_at, disabled_at, disabled_by, updated_at, credential_rotated_at
) on public.devices to authenticated;
revoke select on public.enrollment_tokens from authenticated;
grant select (
  id, organization_id, token_prefix, description, max_uses, use_count, expires_at, status,
  created_by, created_at, revoked_by, revoked_at
) on public.enrollment_tokens to authenticated;

-- ---------- Threat intelligence (platform) ----------
create policy threat_sources_read on public.threat_sources for select to authenticated
  using (public.has_platform_permission('platform.security.threats.read'));
create policy threat_indicators_read on public.threat_indicators for select to authenticated
  using (public.has_platform_permission('platform.security.threats.read'));
create policy threat_observations_read on public.threat_observations for select to authenticated
  using (public.has_platform_permission('platform.security.threats.read'));
create policy allowlist_entries_read on public.allowlist_entries for select to authenticated
  using (
    (organization_id is null and public.has_platform_permission('platform.security.threats.read'))
    or organization_id in (select public.permitted_organization_ids('tenant.policy.read'))
  );

-- ---------- Policy ----------
create policy policies_read on public.policies for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.policy.read')));
create policy policy_rules_read on public.policy_rules for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.policy.read')));
create policy policy_versions_read on public.policy_versions for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.policy.read')));

-- ---------- Events / incidents ----------
create policy security_events_read on public.security_events for select to authenticated
  using (organization_id in (select public.permitted_organization_ids('tenant.events.read')));

create policy incidents_read on public.incidents for select to authenticated
  using (
    organization_id in (select public.permitted_organization_ids('tenant.incident.read'))
    or public.has_platform_permission('platform.security.incidents.read')
  );

create policy endpoint_commands_read on public.endpoint_commands for select to authenticated
  using (
    organization_id in (select public.permitted_organization_ids('tenant.incident.read'))
    or organization_id in (select public.permitted_organization_ids('tenant.devices.manage'))
  );

-- Browser-history evidence requires its own permission, separate from incident read.
create policy incident_artifacts_read on public.incident_artifacts for select to authenticated
  using (
    deleted_at is null
    and (
      (artifact_type <> 'browser_history'
        and organization_id in (select public.permitted_organization_ids('tenant.incident.read')))
      or (artifact_type = 'browser_history'
        and organization_id in (select public.permitted_organization_ids('tenant.incident.history.read')))
    )
  );

-- ---------- Audit ----------
create policy audit_events_read on public.audit_events for select to authenticated
  using (
    public.has_platform_permission('platform.audit.read')
    or (organization_id is not null
        and organization_id in (select public.permitted_organization_ids('tenant.audit.read')))
  );

-- Internal helpers are never callable by API clients.
revoke all on all functions in schema app_private from public, anon, authenticated;
