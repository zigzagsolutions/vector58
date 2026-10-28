-- =============================================================================
-- Global threat intelligence (platform-owned, not tenant data).
-- =============================================================================

create table public.threat_sources (
  id           uuid primary key default gen_random_uuid(),
  name         text not null unique,
  source_type  text not null check (source_type in ('manual', 'internal', 'sample', 'urlhaus', 'openphish', 'phishtank', 'commercial')),
  enabled      boolean not null default true,
  -- Non-secret configuration only. Credentials live in server env / vault.
  config       jsonb not null default '{}'::jsonb,
  default_confidence integer not null default 80 check (default_confidence between 0 and 100),
  last_sync    timestamptz,
  sync_status  text not null default 'never' check (sync_status in ('never', 'running', 'succeeded', 'failed')),
  last_error   text,
  last_stats   jsonb,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create trigger threat_sources_updated_at before update on public.threat_sources
  for each row execute function app_private.set_updated_at();

create table public.threat_indicators (
  id                uuid primary key default gen_random_uuid(),
  indicator_type    text not null check (indicator_type in ('domain', 'exact_url')),
  normalized_value  text not null,
  -- sha256("<indicator_type>:<normalized_value>"), see @bsp/url-normalizer.
  normalized_hash   text not null unique check (normalized_hash ~ '^[0-9a-f]{64}$'),
  hostname          text not null,
  threat_category   text not null check (threat_category in ('phishing', 'malware', 'command-and-control', 'credential-theft', 'fraud', 'malicious-download', 'custom')),
  confidence        integer not null check (confidence between 0 and 100),
  severity          text not null default 'high' check (severity in ('low', 'medium', 'high', 'critical')),
  source            text not null,
  first_seen        timestamptz not null default now(),
  last_seen         timestamptz not null default now(),
  expires_at        timestamptz,
  status            text not null default 'active' check (status in ('active', 'expired', 'revoked')),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index threat_indicators_normalized_value_idx on public.threat_indicators (normalized_value);
create index threat_indicators_hostname_idx on public.threat_indicators (hostname);
create index threat_indicators_active_idx on public.threat_indicators (indicator_type, confidence desc) where status = 'active';
create index threat_indicators_status_idx on public.threat_indicators (status);
create index threat_indicators_expires_idx on public.threat_indicators (expires_at) where status = 'active' and expires_at is not null;
create trigger threat_indicators_updated_at before update on public.threat_indicators
  for each row execute function app_private.set_updated_at();

-- Every sighting of an indicator by a source (append-only provenance).
create table public.threat_observations (
  id               uuid primary key default gen_random_uuid(),
  indicator_id     uuid not null references public.threat_indicators (id),
  source_id        uuid not null references public.threat_sources (id),
  observed_at      timestamptz not null default now(),
  raw_value        text not null,
  threat_category  text not null,
  confidence       integer not null check (confidence between 0 and 100),
  metadata         jsonb not null default '{}'::jsonb
);
create index threat_observations_indicator_idx on public.threat_observations (indicator_id, observed_at desc);
create index threat_observations_source_idx on public.threat_observations (source_id, observed_at desc);
create trigger threat_observations_append_only before update or delete on public.threat_observations
  for each row execute function app_private.prevent_mutation();

-- Known-good allow list. organization_id null = platform-wide safe list that
-- prevents feeds from ever blocking critical infrastructure domains.
-- Tenant-specific allow exceptions are ALLOW_* rules in policy_rules.
create table public.allowlist_entries (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid references public.organizations (id),
  entry_type        text not null check (entry_type in ('domain', 'exact_url')),
  normalized_value  text not null,
  normalized_hash   text not null check (normalized_hash ~ '^[0-9a-f]{64}$'),
  reason            text,
  created_by        uuid references public.profiles (id),
  created_at        timestamptz not null default now()
);
create unique index allowlist_entries_unique on public.allowlist_entries (organization_id, normalized_hash) nulls not distinct;
create index allowlist_entries_organization_id_idx on public.allowlist_entries (organization_id);
create index allowlist_entries_normalized_value_idx on public.allowlist_entries (normalized_value);
