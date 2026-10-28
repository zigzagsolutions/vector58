-- =============================================================================
-- Tenancy, identity and role-based access control.
-- =============================================================================

create table public.profiles (
  id            uuid primary key references auth.users (id) on delete cascade,
  email         text not null,
  display_name  text,
  status        text not null default 'active' check (status in ('active', 'disabled')),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create unique index profiles_email_key on public.profiles (lower(email));
create trigger profiles_updated_at before update on public.profiles
  for each row execute function app_private.set_updated_at();

-- Every auth user gets a profile row.
create or replace function app_private.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    coalesce(new.email, ''),
    nullif(new.raw_user_meta_data ->> 'display_name', '')
  )
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function app_private.handle_new_auth_user();

create table public.organizations (
  id                      uuid primary key default gen_random_uuid(),
  name                    text not null check (char_length(name) between 2 and 120),
  slug                    text not null unique check (slug ~ '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'),
  status                  text not null default 'active' check (status in ('active', 'disabled')),
  -- Commercialisation extension points (unused in Phase 1, kept nullable):
  parent_organization_id  uuid references public.organizations (id),   -- MSP hierarchies
  data_region             text not null default 'default',             -- data residency
  plan_key                text,                                        -- licensing / metering
  device_limit            integer check (device_limit is null or device_limit > 0),
  settings                jsonb not null default '{}'::jsonb,
  created_at              timestamptz not null default now(),
  created_by              uuid references public.profiles (id),
  updated_at              timestamptz not null default now(),
  disabled_at             timestamptz,
  disabled_by             uuid references public.profiles (id)
);
create index organizations_status_idx on public.organizations (status);
create index organizations_parent_idx on public.organizations (parent_organization_id);
create trigger organizations_updated_at before update on public.organizations
  for each row execute function app_private.set_updated_at();

create table public.permissions (
  key          text primary key,
  scope        text not null check (scope in ('platform', 'tenant')),
  description  text not null
);

create table public.roles (
  id               uuid primary key default gen_random_uuid(),
  key              text not null,
  scope            text not null check (scope in ('platform', 'tenant')),
  name             text not null,
  description      text not null default '',
  is_system        boolean not null default true,
  -- null = system role available to every tenant; non-null reserved for custom tenant roles.
  organization_id  uuid references public.organizations (id),
  created_at       timestamptz not null default now(),
  check (scope = 'tenant' or organization_id is null)
);
create unique index roles_key_org_key on public.roles (key, organization_id) nulls not distinct;
create index roles_organization_id_idx on public.roles (organization_id);

create table public.role_permissions (
  role_id         uuid not null references public.roles (id) on delete cascade,
  permission_key  text not null references public.permissions (key) on delete cascade,
  primary key (role_id, permission_key)
);
create index role_permissions_permission_idx on public.role_permissions (permission_key);

-- Tenant roles may only hold tenant permissions. Platform roles may hold
-- platform permissions and tenant permissions; the latter apply only inside an
-- explicitly entered (and audited) tenant context.
create or replace function app_private.check_role_permission_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_role_scope text;
  v_perm_scope text;
begin
  select scope into v_role_scope from public.roles where id = new.role_id;
  select scope into v_perm_scope from public.permissions where key = new.permission_key;
  if v_role_scope = 'tenant' and v_perm_scope <> 'tenant' then
    raise exception 'tenant role cannot hold platform permission %', new.permission_key;
  end if;
  return new;
end;
$$;
create trigger role_permissions_scope_check before insert or update on public.role_permissions
  for each row execute function app_private.check_role_permission_scope();

create table public.platform_user_roles (
  user_id     uuid not null references public.profiles (id) on delete cascade,
  role_id     uuid not null references public.roles (id) on delete cascade,
  granted_by  uuid references public.profiles (id),
  granted_at  timestamptz not null default now(),
  primary key (user_id, role_id)
);

create or replace function app_private.check_platform_role_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if (select scope from public.roles where id = new.role_id) <> 'platform' then
    raise exception 'platform_user_roles may only reference platform roles';
  end if;
  return new;
end;
$$;
create trigger platform_user_roles_scope_check before insert or update on public.platform_user_roles
  for each row execute function app_private.check_platform_role_scope();

create table public.organization_users (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations (id),
  user_id          uuid not null references public.profiles (id) on delete cascade,
  status           text not null default 'active' check (status in ('active', 'invited', 'removed')),
  added_by         uuid references public.profiles (id),
  added_at         timestamptz not null default now(),
  removed_by       uuid references public.profiles (id),
  removed_at       timestamptz,
  unique (organization_id, user_id)
);
create index organization_users_user_idx on public.organization_users (user_id);
create index organization_users_org_status_idx on public.organization_users (organization_id, status);

create table public.organization_user_roles (
  organization_id  uuid not null references public.organizations (id),
  user_id          uuid not null references public.profiles (id) on delete cascade,
  role_id          uuid not null references public.roles (id),
  assigned_by      uuid references public.profiles (id),
  assigned_at      timestamptz not null default now(),
  primary key (organization_id, user_id, role_id),
  foreign key (organization_id, user_id) references public.organization_users (organization_id, user_id) on delete cascade
);
create index organization_user_roles_user_idx on public.organization_user_roles (user_id);
create index organization_user_roles_role_idx on public.organization_user_roles (role_id);

create or replace function app_private.check_tenant_role_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_scope text;
  v_org uuid;
begin
  select scope, organization_id into v_scope, v_org from public.roles where id = new.role_id;
  if v_scope <> 'tenant' then
    raise exception 'organization_user_roles may only reference tenant roles';
  end if;
  if v_org is not null and v_org <> new.organization_id then
    raise exception 'custom role belongs to a different organization';
  end if;
  return new;
end;
$$;
create trigger organization_user_roles_scope_check before insert or update on public.organization_user_roles
  for each row execute function app_private.check_tenant_role_scope();

-- Explicit, time-boxed, audited tenant context for platform users. Platform
-- users never become tenant members and never impersonate tenant users; RLS
-- grants them tenant permissions only while a row here is active.
create table public.platform_tenant_contexts (
  id                uuid primary key default gen_random_uuid(),
  actor_user_id     uuid not null references public.profiles (id) on delete cascade,
  organization_id   uuid not null references public.organizations (id),
  platform_roles    text[] not null,
  reason            text,
  started_at        timestamptz not null default now(),
  expires_at        timestamptz not null,
  ended_at          timestamptz,
  check (expires_at > started_at)
);
create index platform_tenant_contexts_actor_idx on public.platform_tenant_contexts (actor_user_id) where ended_at is null;
create index platform_tenant_contexts_org_idx on public.platform_tenant_contexts (organization_id);
-- One active context per platform user at a time.
create unique index platform_tenant_contexts_one_active on public.platform_tenant_contexts (actor_user_id) where ended_at is null;

create table public.enrollment_tokens (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations (id),
  -- sha256 of the token; plaintext is shown once at creation and never stored.
  token_hash       text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  token_prefix     text not null,
  description      text,
  max_uses         integer not null default 25 check (max_uses > 0),
  use_count        integer not null default 0 check (use_count >= 0),
  expires_at       timestamptz not null,
  status           text not null default 'active' check (status in ('active', 'revoked', 'exhausted')),
  created_by       uuid references public.profiles (id),
  created_at       timestamptz not null default now(),
  revoked_by       uuid references public.profiles (id),
  revoked_at       timestamptz
);
create index enrollment_tokens_organization_id_idx on public.enrollment_tokens (organization_id);
create index enrollment_tokens_status_idx on public.enrollment_tokens (status);
