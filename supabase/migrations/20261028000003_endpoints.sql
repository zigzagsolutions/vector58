-- =============================================================================
-- Endpoints: devices, browser clients, release channels.
-- =============================================================================

create table public.devices (
  id                     uuid primary key default gen_random_uuid(),
  organization_id        uuid not null references public.organizations (id),
  -- Agent-generated persistent install id. Unique per tenant so re-enrollment
  -- of the same machine updates rather than duplicates.
  installation_id        uuid not null,
  hostname               text not null,
  os_version             text,
  agent_version          text,
  local_ip               text,
  -- Determined server-side from the request source; never client-supplied.
  public_ip              text,
  machine                jsonb not null default '{}'::jsonb,
  status                 text not null default 'active' check (status in ('active', 'disabled')),
  -- sha256 of the device bearer secret. Replaced by public_key auth in Phase 2.
  credential_hash        text not null check (credential_hash ~ '^[0-9a-f]{64}$'),
  credential_rotated_at  timestamptz not null default now(),
  public_key             text,
  policy_id              uuid,
  policy_version         integer,
  policy_checksum        text,
  enrolled_at            timestamptz not null default now(),
  enrollment_token_id    uuid references public.enrollment_tokens (id),
  last_heartbeat_at      timestamptz,
  disabled_at            timestamptz,
  disabled_by            uuid references public.profiles (id),
  updated_at             timestamptz not null default now(),
  unique (organization_id, installation_id),
  -- Composite key lets child tables enforce same-tenant references.
  unique (id, organization_id)
);
create index devices_organization_id_idx on public.devices (organization_id);
create index devices_hostname_idx on public.devices (organization_id, lower(hostname));
create index devices_last_heartbeat_idx on public.devices (organization_id, last_heartbeat_at desc);
create index devices_status_idx on public.devices (organization_id, status);
create trigger devices_updated_at before update on public.devices
  for each row execute function app_private.set_updated_at();

create table public.browser_clients (
  id                 uuid primary key default gen_random_uuid(),
  organization_id    uuid not null,
  device_id          uuid not null,
  client_id          text not null,
  browser            text not null check (browser in ('chrome', 'edge')),
  browser_version    text,
  extension_version  text,
  policy_version     integer,
  native_connected   boolean not null default false,
  dnr_rule_count     integer,
  first_seen_at      timestamptz not null default now(),
  last_seen_at       timestamptz not null default now(),
  unique (device_id, client_id),
  foreign key (device_id, organization_id) references public.devices (id, organization_id) on delete cascade
);
create index browser_clients_organization_id_idx on public.browser_clients (organization_id);
create index browser_clients_device_id_idx on public.browser_clients (device_id);

-- Platform-owned release catalogs (no tenant data).
create table public.agent_releases (
  id            uuid primary key default gen_random_uuid(),
  version       text not null,
  channel       text not null default 'stable' check (channel in ('stable', 'beta', 'canary')),
  download_url  text,
  sha256        text check (sha256 is null or sha256 ~ '^[0-9a-f]{64}$'),
  -- Authenticode / detached signature reference. Agents must refuse unsigned binaries.
  signature     text,
  status        text not null default 'draft' check (status in ('draft', 'released', 'revoked')),
  released_at   timestamptz,
  created_at    timestamptz not null default now(),
  unique (version, channel)
);
create index agent_releases_status_idx on public.agent_releases (status);

create table public.extension_releases (
  id            uuid primary key default gen_random_uuid(),
  browser       text not null check (browser in ('chrome', 'edge')),
  version       text not null,
  extension_id  text not null,
  channel       text not null default 'stable' check (channel in ('stable', 'beta', 'canary')),
  status        text not null default 'draft' check (status in ('draft', 'released', 'revoked')),
  released_at   timestamptz,
  created_at    timestamptz not null default now(),
  unique (browser, version, channel)
);
create index extension_releases_status_idx on public.extension_releases (status);
