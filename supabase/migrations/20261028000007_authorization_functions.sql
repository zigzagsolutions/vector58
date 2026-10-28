-- =============================================================================
-- Authorization functions shared by RLS policies and server-side checks.
-- Mirrors packages/auth-permissions/src/evaluate.ts.
--
-- SECURITY DEFINER so policies can consult RBAC tables without granting
-- clients read access to them; search_path is pinned to '' to prevent
-- search-path hijacking. All functions are keyed on auth.uid(), so a caller
-- can only ever learn about their own access.
-- =============================================================================

-- Organizations in which the current user holds `p_permission`, either as an
-- active member of an active organization, or as a platform user inside an
-- explicitly entered, unexpired tenant context.
create or replace function public.permitted_organization_ids(p_permission text)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select ou.organization_id
  from public.organization_users ou
  join public.organizations o on o.id = ou.organization_id and o.status = 'active'
  join public.organization_user_roles our
    on our.organization_id = ou.organization_id and our.user_id = ou.user_id
  join public.role_permissions rp on rp.role_id = our.role_id
  join public.profiles p on p.id = ou.user_id and p.status = 'active'
  where ou.user_id = auth.uid()
    and ou.status = 'active'
    and rp.permission_key = p_permission
  union
  select c.organization_id
  from public.platform_tenant_contexts c
  join public.platform_user_roles pur on pur.user_id = c.actor_user_id
  join public.role_permissions rp on rp.role_id = pur.role_id
  join public.profiles p on p.id = c.actor_user_id and p.status = 'active'
  where c.actor_user_id = auth.uid()
    and c.ended_at is null
    and c.expires_at > now()
    and rp.permission_key = p_permission;
$$;

create or replace function public.has_tenant_permission(p_organization_id uuid, p_permission text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.permitted_organization_ids(p_permission) id where id = p_organization_id
  );
$$;

create or replace function public.has_platform_permission(p_permission text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.platform_user_roles pur
    join public.roles r on r.id = pur.role_id and r.scope = 'platform'
    join public.role_permissions rp on rp.role_id = pur.role_id
    join public.permissions perm on perm.key = rp.permission_key and perm.scope = 'platform'
    join public.profiles p on p.id = pur.user_id and p.status = 'active'
    where pur.user_id = auth.uid()
      and rp.permission_key = p_permission
  );
$$;

-- Organizations visible at all to the current user (any membership or context or platform read).
create or replace function public.visible_organization_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select ou.organization_id
  from public.organization_users ou
  join public.organizations o on o.id = ou.organization_id and o.status = 'active'
  where ou.user_id = auth.uid() and ou.status = 'active'
  union
  select c.organization_id
  from public.platform_tenant_contexts c
  where c.actor_user_id = auth.uid() and c.ended_at is null and c.expires_at > now()
  union
  select o.id from public.organizations o where public.has_platform_permission('platform.tenants.read');
$$;

-- Effective tenant permissions for the current user in one organization (used by the portal).
create or replace function public.my_tenant_permissions(p_organization_id uuid)
returns setof text
language sql
stable
security definer
set search_path = ''
as $$
  select perm.key
  from public.permissions perm
  where perm.scope = 'tenant'
    and public.has_tenant_permission(p_organization_id, perm.key);
$$;

revoke all on function public.permitted_organization_ids(text) from public;
revoke all on function public.has_tenant_permission(uuid, text) from public;
revoke all on function public.has_platform_permission(text) from public;
revoke all on function public.visible_organization_ids() from public;
revoke all on function public.my_tenant_permissions(uuid) from public;
grant execute on function public.permitted_organization_ids(text) to authenticated;
grant execute on function public.has_tenant_permission(uuid, text) to authenticated;
grant execute on function public.has_platform_permission(text) to authenticated;
grant execute on function public.visible_organization_ids() to authenticated;
grant execute on function public.my_tenant_permissions(uuid) to authenticated;
