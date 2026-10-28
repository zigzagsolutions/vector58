import { ORG_INTERNAL, asService } from '../fixtures/db';

export const INTERNAL_DEVICE = '00000000-0000-4f30-8000-000000000001';

/** Mirror the seeded Acme data inside Internal so every cross-tenant check has a positive control. */
export async function ensureInternalFixtures() {
  await asService(async (c) => {
    await c.query(
      `insert into public.devices (id, organization_id, installation_id, hostname, status, credential_hash)
       values ($1, $2, gen_random_uuid(), 'INTERNAL-WS-001', 'active', repeat('a', 64))
       on conflict (id) do nothing`,
      [INTERNAL_DEVICE, ORG_INTERNAL],
    );
    await c.query(
      `insert into public.security_events (organization_id, device_id, source_event_id, event_type, occurred_at, domain)
       values ($1, $2, '00000000-0000-4f40-8000-000000000099', 'URL_BLOCKED', now(), 'internal-only.example')
       on conflict do nothing`,
      [ORG_INTERNAL, INTERNAL_DEVICE],
    );
    await c.query(
      `insert into public.incidents (id, organization_id, title) values ('00000000-0000-4f50-8000-000000000001', $1, 'Internal incident')
       on conflict (id) do nothing`,
      [ORG_INTERNAL],
    );
    await c.query(
      `insert into public.audit_events (organization_id, actor_scope, action) values ($1, 'system', 'TEST_INTERNAL_AUDIT')`,
      [ORG_INTERNAL],
    );
  });
}
