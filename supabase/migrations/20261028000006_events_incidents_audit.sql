-- =============================================================================
-- Security events, incident response and audit.
-- =============================================================================

create table public.security_events (
  id                 uuid primary key default gen_random_uuid(),
  organization_id    uuid not null references public.organizations (id),
  device_id          uuid,
  -- Endpoint-generated id; makes ingestion idempotent across agent retries.
  source_event_id    uuid not null,
  browser_client_id  text,
  event_type         text not null check (event_type in (
                       'URL_BLOCKED', 'POLICY_APPLIED', 'POLICY_FAILED', 'EXTENSION_CONNECTED',
                       'EXTENSION_DISCONNECTED', 'DEVICE_ENROLLED', 'AGENT_STARTED', 'AGENT_HEARTBEAT')),
  occurred_at        timestamptz not null,
  received_at        timestamptz not null default now(),
  url                text,
  domain             text,
  rule_id            integer,
  policy_version     integer,
  threat_category    text,
  browser            text check (browser is null or browser in ('chrome', 'edge')),
  browser_version    text,
  extension_version  text,
  agent_version      text,
  hostname           text,
  details            jsonb not null default '{}'::jsonb,
  unique (device_id, source_event_id),
  foreign key (device_id, organization_id) references public.devices (id, organization_id)
);
create index security_events_org_time_idx on public.security_events (organization_id, occurred_at desc);
create index security_events_device_idx on public.security_events (device_id, occurred_at desc);
create index security_events_type_idx on public.security_events (organization_id, event_type, occurred_at desc);
create index security_events_domain_idx on public.security_events (organization_id, domain);
create index security_events_hostname_idx on public.security_events (organization_id, hostname);
create index security_events_policy_version_idx on public.security_events (organization_id, policy_version);
create index security_events_occurred_at_idx on public.security_events (occurred_at);

create table public.incidents (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null references public.organizations (id),
  title            text not null check (char_length(title) between 3 and 200),
  description      text,
  severity         text not null default 'medium' check (severity in ('low', 'medium', 'high', 'critical')),
  status           text not null default 'open' check (status in ('open', 'investigating', 'contained', 'closed')),
  created_by       uuid references public.profiles (id),
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  closed_at        timestamptz,
  unique (id, organization_id)
);
create index incidents_organization_id_idx on public.incidents (organization_id);
create index incidents_status_idx on public.incidents (organization_id, status);
create trigger incidents_updated_at before update on public.incidents
  for each row execute function app_private.set_updated_at();

create table public.endpoint_commands (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null,
  device_id        uuid not null,
  incident_id      uuid,
  command_type     text not null check (command_type in ('REFRESH_POLICY', 'COLLECT_DIAGNOSTICS', 'CHECK_EXTENSION_STATUS', 'COLLECT_BROWSER_HISTORY')),
  payload          jsonb not null default '{}'::jsonb,
  status           text not null default 'PENDING' check (status in ('PENDING', 'RECEIVED', 'RUNNING', 'COMPLETED', 'FAILED', 'EXPIRED')),
  issued_by        uuid references public.profiles (id),
  approved_by      uuid references public.profiles (id),
  issued_at        timestamptz not null default now(),
  expires_at       timestamptz not null,
  received_at      timestamptz,
  started_at       timestamptz,
  completed_at     timestamptz,
  result           jsonb,
  error            text,
  foreign key (device_id, organization_id) references public.devices (id, organization_id),
  foreign key (incident_id, organization_id) references public.incidents (id, organization_id),
  -- History collection is only ever incident-triggered and explicitly approved.
  check (command_type <> 'COLLECT_BROWSER_HISTORY' or (incident_id is not null and approved_by is not null))
);
create index endpoint_commands_organization_id_idx on public.endpoint_commands (organization_id);
create index endpoint_commands_device_status_idx on public.endpoint_commands (device_id, status);
create index endpoint_commands_incident_id_idx on public.endpoint_commands (incident_id);
create index endpoint_commands_status_idx on public.endpoint_commands (status, expires_at);

create table public.incident_artifacts (
  id               uuid primary key default gen_random_uuid(),
  organization_id  uuid not null,
  incident_id      uuid not null,
  command_id       uuid references public.endpoint_commands (id),
  artifact_type    text not null check (artifact_type in ('diagnostics', 'extension_status', 'browser_history', 'note')),
  content          jsonb,
  storage_ref      text,
  sha256           text,
  retention_until  timestamptz,
  created_by       uuid references public.profiles (id),
  created_at       timestamptz not null default now(),
  deleted_at       timestamptz,
  deleted_by       uuid references public.profiles (id),
  foreign key (incident_id, organization_id) references public.incidents (id, organization_id)
);
create index incident_artifacts_organization_id_idx on public.incident_artifacts (organization_id);
create index incident_artifacts_incident_id_idx on public.incident_artifacts (incident_id);

-- Append-only audit trail. organization_id is null for platform-scope actions.
create table public.audit_events (
  id                 uuid primary key default gen_random_uuid(),
  organization_id    uuid references public.organizations (id),
  actor_user_id      uuid references public.profiles (id),
  -- Snapshot of the actor's email at the time of the action (identity survives profile changes).
  actor_email        text,
  actor_device_id    uuid,
  actor_scope        text not null check (actor_scope in ('platform', 'tenant', 'device', 'system')),
  platform_role      text,
  tenant_role        text,
  tenant_context_id  uuid references public.platform_tenant_contexts (id),
  action             text not null,
  target_type        text,
  target_id          text,
  occurred_at        timestamptz not null default now(),
  ip_address         text,
  user_agent         text,
  metadata           jsonb not null default '{}'::jsonb
);
create index audit_events_organization_id_idx on public.audit_events (organization_id, occurred_at desc);
create index audit_events_actor_idx on public.audit_events (actor_user_id, occurred_at desc);
create index audit_events_action_idx on public.audit_events (action, occurred_at desc);
create index audit_events_occurred_at_idx on public.audit_events (occurred_at desc);
create trigger audit_events_append_only before update or delete on public.audit_events
  for each row execute function app_private.prevent_mutation();
-- TRUNCATE bypasses row triggers; block it too.
create trigger audit_events_no_truncate before truncate on public.audit_events
  for each statement execute function app_private.prevent_mutation();
