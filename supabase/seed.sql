-- =============================================================================
-- DEVELOPMENT SEED DATA - never run against production.
--
-- Organizations: Internal Company (tenant #1, not special-cased) and Acme Corporation.
-- All seeded users share the password:  Vector58-Dev!
-- Dev enrollment tokens (plaintext shown here ONLY because this is dev data):
--   Internal Company: dev-internal-enroll-token-0000000001
--   Acme Corporation: dev-acme-enroll-token-00000000000001
-- =============================================================================

-- ---------- Organizations ----------
insert into public.organizations (id, name, slug, status) values
  ('00000000-0000-4000-a000-000000000001', 'Internal Company', 'internal', 'active'),
  ('00000000-0000-4000-a000-000000000002', 'Acme Corporation', 'acme', 'active')
on conflict (id) do nothing;

-- ---------- Auth users (Supabase GoTrue compatible) ----------
with seed_users (id, email, display_name) as (
  values
    ('00000000-0000-4000-b000-000000000001'::uuid, 'platform.superadmin@vector58.test', 'Platform Super Admin'),
    ('00000000-0000-4000-b000-000000000002'::uuid, 'platform.security@vector58.test',   'Platform Security Admin'),
    ('00000000-0000-4000-b000-000000000003'::uuid, 'platform.support@vector58.test',    'Platform Support'),
    ('00000000-0000-4000-b000-000000000004'::uuid, 'platform.auditor@vector58.test',    'Platform Auditor'),
    ('00000000-0000-4000-c000-000000000001'::uuid, 'owner@internal.test',               'Internal Owner'),
    ('00000000-0000-4000-c000-000000000002'::uuid, 'secadmin@internal.test',            'Internal Security Admin'),
    ('00000000-0000-4000-c000-000000000003'::uuid, 'analyst@internal.test',             'Internal Security Analyst'),
    ('00000000-0000-4000-c000-000000000004'::uuid, 'helpdesk@internal.test',            'Internal Help Desk'),
    ('00000000-0000-4000-d000-000000000001'::uuid, 'owner@acme.test',                   'Acme Owner'),
    ('00000000-0000-4000-d000-000000000002'::uuid, 'secadmin@acme.test',                'Acme Security Admin'),
    ('00000000-0000-4000-d000-000000000003'::uuid, 'analyst@acme.test',                 'Acme Security Analyst'),
    ('00000000-0000-4000-d000-000000000004'::uuid, 'helpdesk@acme.test',                'Acme Help Desk'),
    -- Unassigned user used by the acceptance demo ("Add Tenant Security Admin").
    ('00000000-0000-4000-e000-000000000001'::uuid, 'new.secadmin@demo.test',            'Demo Security Admin')
)
insert into auth.users (
  instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
  confirmation_token, recovery_token, email_change_token_new, email_change,
  email_change_token_current, phone_change, phone_change_token, reauthentication_token
)
select
  '00000000-0000-0000-0000-000000000000', id, 'authenticated', 'authenticated', email,
  extensions.crypt('Vector58-Dev!', extensions.gen_salt('bf')), now(),
  '{"provider":"email","providers":["email"]}'::jsonb,
  jsonb_build_object('display_name', display_name), now(), now(),
  '', '', '', '', '', '', '', ''
from seed_users
on conflict (id) do nothing;

insert into auth.identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
select gen_random_uuid(), u.id::text, u.id,
       jsonb_build_object('sub', u.id::text, 'email', u.email, 'email_verified', true),
       'email', now(), now(), now()
from auth.users u
where u.email like '%.test'
  and not exists (select 1 from auth.identities i where i.user_id = u.id and i.provider = 'email');

-- ---------- Platform roles ----------
insert into public.platform_user_roles (user_id, role_id)
select v.user_id, r.id
from (values
  ('00000000-0000-4000-b000-000000000001'::uuid, 'PlatformSuperAdmin'),
  ('00000000-0000-4000-b000-000000000002'::uuid, 'PlatformSecurityAdmin'),
  ('00000000-0000-4000-b000-000000000003'::uuid, 'PlatformSupport'),
  ('00000000-0000-4000-b000-000000000004'::uuid, 'PlatformAuditor')
) as v(user_id, role_key)
join public.roles r on r.key = v.role_key and r.organization_id is null
on conflict do nothing;

-- ---------- Tenant memberships ----------
insert into public.organization_users (organization_id, user_id, status)
select v.org_id, v.user_id, 'active'
from (values
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000001'::uuid),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000002'::uuid),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000003'::uuid),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000004'::uuid),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000001'::uuid),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000002'::uuid),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000003'::uuid),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000004'::uuid)
) as v(org_id, user_id)
on conflict do nothing;

insert into public.organization_user_roles (organization_id, user_id, role_id)
select v.org_id, v.user_id, r.id
from (values
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000001'::uuid, 'TenantOwner'),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000002'::uuid, 'TenantSecurityAdmin'),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000003'::uuid, 'TenantSecurityAnalyst'),
  ('00000000-0000-4000-a000-000000000001'::uuid, '00000000-0000-4000-c000-000000000004'::uuid, 'TenantHelpDesk'),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000001'::uuid, 'TenantOwner'),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000002'::uuid, 'TenantSecurityAdmin'),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000003'::uuid, 'TenantSecurityAnalyst'),
  ('00000000-0000-4000-a000-000000000002'::uuid, '00000000-0000-4000-d000-000000000004'::uuid, 'TenantHelpDesk')
) as v(org_id, user_id, role_key)
join public.roles r on r.key = v.role_key and r.organization_id is null
on conflict do nothing;

-- ---------- Default policies ----------
insert into public.policies (id, organization_id, name, description, is_default, include_global_threats) values
  ('00000000-0000-4000-f100-000000000001', '00000000-0000-4000-a000-000000000001', 'Default Policy', 'Applied to all enrolled devices', true, true),
  ('00000000-0000-4000-f100-000000000002', '00000000-0000-4000-a000-000000000002', 'Default Policy', 'Applied to all enrolled devices', true, true)
on conflict (id) do nothing;

insert into public.policy_rules (organization_id, policy_id, rule_type, normalized_value, normalized_hash, priority, category, reason)
values
  ('00000000-0000-4000-a000-000000000002', '00000000-0000-4000-f100-000000000002', 'BLOCK_DOMAIN', 'acme-only-block.example',
   encode(extensions.digest('domain:acme-only-block.example', 'sha256'), 'hex'), 100, 'phishing', 'Seeded Acme rule')
on conflict do nothing;

-- ---------- Enrollment tokens (dev) ----------
insert into public.enrollment_tokens (id, organization_id, token_hash, token_prefix, description, max_uses, expires_at) values
  ('00000000-0000-4000-f200-000000000001', '00000000-0000-4000-a000-000000000001',
   encode(extensions.digest('dev-internal-enroll-token-0000000001', 'sha256'), 'hex'), 'dev-inte', 'Development token', 1000, now() + interval '365 days'),
  ('00000000-0000-4000-f200-000000000002', '00000000-0000-4000-a000-000000000002',
   encode(extensions.digest('dev-acme-enroll-token-00000000000001', 'sha256'), 'hex'), 'dev-acme', 'Development token', 1000, now() + interval '365 days')
on conflict (id) do nothing;

-- ---------- Sample Acme device + events (gives tenant-isolation tests real data) ----------
insert into public.devices (id, organization_id, installation_id, hostname, os_version, agent_version, local_ip, status, credential_hash, last_heartbeat_at)
values
  ('00000000-0000-4000-f300-000000000002', '00000000-0000-4000-a000-000000000002', '00000000-0000-4000-f301-000000000002',
   'ACME-LT-042', 'Windows 11 Enterprise 24H2', '0.1.0', '10.20.0.42', 'active',
   encode(extensions.digest('seed-only-not-a-real-device-secret-acme', 'sha256'), 'hex'), now() - interval '2 hours')
on conflict (id) do nothing;

insert into public.security_events (organization_id, device_id, source_event_id, event_type, occurred_at, url, domain, rule_id, policy_version, threat_category, browser, hostname)
values
  ('00000000-0000-4000-a000-000000000002', '00000000-0000-4000-f300-000000000002', '00000000-0000-4000-f400-000000000001',
   'URL_BLOCKED', now() - interval '3 hours', 'https://acme-only-block.example/', 'acme-only-block.example', 1, 1, 'phishing', 'chrome', 'ACME-LT-042')
on conflict do nothing;

insert into public.incidents (id, organization_id, title, description, severity, created_by)
values ('00000000-0000-4000-f500-000000000002', '00000000-0000-4000-a000-000000000002', 'Acme seeded incident',
        'Suspicious credential harvesting page reported by finance', 'high', '00000000-0000-4000-d000-000000000001')
on conflict (id) do nothing;

insert into public.audit_events (organization_id, actor_user_id, actor_scope, tenant_role, action, target_type, target_id, metadata)
values ('00000000-0000-4000-a000-000000000002', '00000000-0000-4000-d000-000000000001', 'tenant', 'TenantOwner',
        'INCIDENT_CREATED', 'incident', '00000000-0000-4000-f500-000000000002', '{"seed": true}');

-- ---------- Global threat intelligence ----------
insert into public.threat_sources (id, name, source_type, enabled, default_confidence) values
  ('00000000-0000-4000-f600-000000000001', 'Manual (Platform Security)', 'manual', true, 95),
  ('00000000-0000-4000-f600-000000000002', 'Sample Feed', 'sample', true, 85)
on conflict (id) do nothing;

insert into public.threat_indicators (indicator_type, normalized_value, normalized_hash, hostname, threat_category, confidence, severity, source)
values
  ('domain', 'global-malware-test.example', encode(extensions.digest('domain:global-malware-test.example', 'sha256'), 'hex'),
   'global-malware-test.example', 'malware', 95, 'critical', 'Manual (Platform Security)'),
  ('domain', 'global-phish-test.example', encode(extensions.digest('domain:global-phish-test.example', 'sha256'), 'hex'),
   'global-phish-test.example', 'phishing', 90, 'high', 'Manual (Platform Security)')
on conflict (normalized_hash) do nothing;

-- Platform-wide safe list: feeds can never block these.
insert into public.allowlist_entries (organization_id, entry_type, normalized_value, normalized_hash, reason)
select null, 'domain', d, encode(extensions.digest('domain:' || d, 'sha256'), 'hex'), 'Critical infrastructure safe list'
from unnest(array['microsoft.com', 'windowsupdate.com', 'google.com', 'supabase.co', 'vercel.app']) as d
on conflict do nothing;
