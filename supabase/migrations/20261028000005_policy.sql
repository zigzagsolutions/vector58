-- =============================================================================
-- Tenant policies, rules and immutable policy versions.
-- =============================================================================

create table public.policies (
  id                      uuid primary key default gen_random_uuid(),
  organization_id         uuid not null references public.organizations (id),
  name                    text not null check (char_length(name) between 1 and 120),
  description             text,
  is_default              boolean not null default false,
  include_global_threats  boolean not null default true,
  min_global_confidence   integer not null default 75 check (min_global_confidence between 0 and 100),
  status                  text not null default 'active' check (status in ('active', 'archived')),
  current_version_number  integer,
  current_version_id      uuid,
  created_by              uuid references public.profiles (id),
  created_at              timestamptz not null default now(),
  updated_at              timestamptz not null default now(),
  unique (id, organization_id)
);
create index policies_organization_id_idx on public.policies (organization_id);
create unique index policies_one_default on public.policies (organization_id) where is_default;
create trigger policies_updated_at before update on public.policies
  for each row execute function app_private.set_updated_at();

alter table public.devices
  add constraint devices_policy_fk foreign key (policy_id, organization_id)
  references public.policies (id, organization_id);

create table public.policy_rules (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid not null,
  policy_id         uuid not null,
  rule_type         text not null check (rule_type in ('BLOCK_DOMAIN', 'BLOCK_URL', 'ALLOW_DOMAIN', 'ALLOW_URL')),
  normalized_value  text not null,
  normalized_hash   text not null check (normalized_hash ~ '^[0-9a-f]{64}$'),
  priority          integer not null default 100 check (priority between 0 and 999),
  enabled           boolean not null default true,
  category          text not null default 'custom' check (category in ('phishing', 'malware', 'command-and-control', 'credential-theft', 'fraud', 'malicious-download', 'custom')),
  reason            text,
  created_by        uuid references public.profiles (id),
  created_at        timestamptz not null default now(),
  expires_at        timestamptz,
  -- Soft delete keeps provenance for audit and old policy versions.
  deleted_at        timestamptz,
  deleted_by        uuid references public.profiles (id),
  foreign key (policy_id, organization_id) references public.policies (id, organization_id)
);
create index policy_rules_organization_id_idx on public.policy_rules (organization_id);
create index policy_rules_policy_id_idx on public.policy_rules (policy_id) where deleted_at is null;
create index policy_rules_normalized_value_idx on public.policy_rules (normalized_value);
-- Duplicate normalized entries per policy/rule type are rejected.
create unique index policy_rules_unique_live on public.policy_rules (policy_id, rule_type, normalized_hash) where deleted_at is null;

create table public.policy_versions (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid not null,
  policy_id         uuid not null,
  version_number    integer not null check (version_number > 0),
  schema_version    integer not null,
  rule_count        integer not null check (rule_count >= 0),
  checksum          text not null check (checksum ~ '^[0-9a-f]{64}$'),
  compiled_payload  jsonb,
  -- For large payloads stored in object storage (Phase 2).
  payload_ref       text,
  compiler_stats    jsonb not null default '{}'::jsonb,
  created_by        uuid references public.profiles (id),
  created_at        timestamptz not null default now(),
  published_at      timestamptz not null default now(),
  status            text not null default 'published' check (status in ('published', 'superseded')),
  unique (policy_id, version_number),
  check (compiled_payload is not null or payload_ref is not null),
  foreign key (policy_id, organization_id) references public.policies (id, organization_id)
);
create index policy_versions_organization_id_idx on public.policy_versions (organization_id);
create index policy_versions_policy_version_idx on public.policy_versions (policy_id, version_number desc);
create index policy_versions_status_idx on public.policy_versions (organization_id, status);

alter table public.policies
  add constraint policies_current_version_fk foreign key (current_version_id) references public.policy_versions (id);

-- Policy versions are immutable. The only permitted change is the lifecycle
-- transition published -> superseded when a newer version is published.
create or replace function app_private.protect_policy_versions()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'policy_versions are immutable and cannot be deleted' using errcode = 'insufficient_privilege';
  end if;
  if (to_jsonb(new) - 'status') is distinct from (to_jsonb(old) - 'status')
     or not (old.status = 'published' and new.status = 'superseded') then
    raise exception 'policy_versions are immutable (only published -> superseded is allowed)'
      using errcode = 'insufficient_privilege';
  end if;
  return new;
end;
$$;
create trigger policy_versions_immutable before update or delete on public.policy_versions
  for each row execute function app_private.protect_policy_versions();
