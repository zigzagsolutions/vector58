-- =============================================================================
-- Foundation: extensions, private schema, shared trigger helpers.
-- All schema changes live in migrations; nothing is created by hand.
-- =============================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- Private schema for helpers that must never be exposed through PostgREST.
create schema if not exists app_private;
revoke all on schema app_private from public;

create or replace function app_private.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- Generic guard used by append-only tables (audit_events, threat_observations).
create or replace function app_private.prevent_mutation()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% on %.% is not permitted: table is append-only',
    tg_op, tg_table_schema, tg_table_name
    using errcode = 'insufficient_privilege';
end;
$$;
