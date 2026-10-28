/**
 * Tenant isolation at the database layer. These tests execute real SQL as the
 * `authenticated` role with Supabase-style JWT claims, i.e. exactly what a
 * browser holding the publishable key + a user session could do directly
 * against PostgREST. UI-level hiding is NOT what is being tested here.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ACME_DEVICE, ORG_ACME, ORG_INTERNAL, USERS, asService, asUser, closePool, count } from '../fixtures/db';
import { INTERNAL_DEVICE, ensureInternalFixtures } from './seed-fixtures';

const TENANT_TABLES = [
  ['devices', 'id'],
  ['browser_clients', 'id'],
  ['policies', 'id'],
  ['policy_rules', 'id'],
  ['policy_versions', 'id'],
  ['security_events', 'id'],
  ['incidents', 'id'],
  ['endpoint_commands', 'id'],
  ['incident_artifacts', 'id'],
  ['audit_events', 'id'],
  ['enrollment_tokens', 'id'],
  ['organization_users', 'id'],
] as const;

beforeAll(ensureInternalFixtures);
afterAll(closePool);

describe('schema guarantees', () => {
  it('RLS is enabled on every public table', async () => {
    const rows = await asService((c) =>
      c.query<{ tablename: string; rowsecurity: boolean }>(
        `select c.relname as tablename, c.relrowsecurity as rowsecurity
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind = 'r'`,
      ),
    );
    expect(rows.rows.length).toBeGreaterThanOrEqual(25);
    expect(rows.rows.filter((r) => !r.rowsecurity)).toEqual([]);
  });

  it('every tenant-owned table carries organization_id', async () => {
    const tenantOwned = [
      'organization_users', 'organization_user_roles', 'devices', 'browser_clients', 'policies', 'policy_rules',
      'policy_versions', 'security_events', 'endpoint_commands', 'incidents', 'incident_artifacts',
      'enrollment_tokens', 'audit_events', 'allowlist_entries', 'platform_tenant_contexts',
    ];
    const rows = await asService((c) =>
      c.query<{ table_name: string }>(
        `select table_name from information_schema.columns
         where table_schema = 'public' and column_name = 'organization_id'`,
      ),
    );
    const withOrg = new Set(rows.rows.map((r) => r.table_name));
    expect(tenantOwned.filter((t) => !withOrg.has(t))).toEqual([]);
  });

  it('browser roles hold no write privilege on any table', async () => {
    const rows = await asService((c) =>
      c.query(
        `select table_name, privilege_type, grantee from information_schema.role_table_grants
         where table_schema = 'public' and grantee in ('anon', 'authenticated')
           and privilege_type in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')`,
      ),
    );
    expect(rows.rows).toEqual([]);
  });
});

describe('Tenant A cannot read Tenant B', () => {
  const pairs = [
    { name: 'Acme owner', user: USERS.acmeOwner, own: ORG_ACME, other: ORG_INTERNAL },
    { name: 'Acme security admin', user: USERS.acmeSecAdmin, own: ORG_ACME, other: ORG_INTERNAL },
    { name: 'Internal owner', user: USERS.internalOwner, own: ORG_INTERNAL, other: ORG_ACME },
    { name: 'Internal security admin', user: USERS.internalSecAdmin, own: ORG_INTERNAL, other: ORG_ACME },
  ];

  for (const p of pairs) {
    for (const [table] of TENANT_TABLES) {
      it(`${p.name}: ${table} of the other tenant is invisible`, async () => {
        await asUser(p.user, async (c) => {
          expect(await count(c, `select 1 from public.${table} where organization_id = $1`, [p.other])).toBe(0);
        });
      });
    }
    it(`${p.name}: cannot see the other organization row`, async () => {
      await asUser(p.user, async (c) => {
        expect(await count(c, `select 1 from public.organizations where id = $1`, [p.other])).toBe(0);
        expect(await count(c, `select 1 from public.organizations`)).toBe(1);
      });
    });
    it(`${p.name}: positive control - own devices, policies, events, incidents, audit are visible`, async () => {
      await asUser(p.user, async (c) => {
        expect(await count(c, `select 1 from public.devices where organization_id = $1`, [p.own])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.policies where organization_id = $1`, [p.own])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.security_events where organization_id = $1`, [p.own])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.incidents where organization_id = $1`, [p.own])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.audit_events where organization_id = $1`, [p.own])).toBeGreaterThan(0);
      });
    });
  }

  it('changing organization_id in a filter does not help (Acme analyst targeting Internal device by id)', async () => {
    await asUser(USERS.acmeAnalyst, async (c) => {
      expect(await count(c, `select 1 from public.devices where id = $1`, [INTERNAL_DEVICE])).toBe(0);
      expect(await count(c, `select 1 from public.devices where id = $1`, [ACME_DEVICE])).toBe(1);
    });
  });

  it('tenant users cannot write anything directly, even in their own tenant', async () => {
    await asUser(USERS.acmeOwner, async (c) => {
      await expect(
        c.query(`insert into public.policy_rules (organization_id, policy_id, rule_type, normalized_value, normalized_hash)
                 values ($1, '00000000-0000-4000-f100-000000000002', 'BLOCK_DOMAIN', 'x.example', repeat('b', 64))`, [ORG_ACME]),
      ).rejects.toThrow(/permission denied/);
    });
    await asUser(USERS.acmeOwner, async (c) => {
      await expect(c.query(`update public.organizations set name = 'pwned' where id = $1`, [ORG_INTERNAL])).rejects.toThrow(/permission denied/);
    });
    await asUser(USERS.acmeOwner, async (c) => {
      await expect(c.query(`delete from public.security_events`)).rejects.toThrow(/permission denied/);
    });
  });

  it('device credential hashes are never readable by browser sessions', async () => {
    await asUser(USERS.acmeOwner, async (c) => {
      await expect(c.query(`select credential_hash from public.devices`)).rejects.toThrow(/permission denied/);
    });
    await asUser(USERS.acmeOwner, async (c) => {
      await expect(c.query(`select token_hash from public.enrollment_tokens`)).rejects.toThrow(/permission denied/);
    });
  });

  it('authorization helpers do not leak other tenants', async () => {
    await asUser(USERS.acmeOwner, async (c) => {
      const r = await c.query(`select public.has_tenant_permission($1, 'tenant.devices.read') as a,
                                      public.has_tenant_permission($2, 'tenant.devices.read') as b`, [ORG_INTERNAL, ORG_ACME]);
      expect(r.rows[0]).toEqual({ a: false, b: true });
    });
  });
});

describe('permission-granular access within a tenant', () => {
  it('help desk sees devices and events but not incidents or audit', async () => {
    await asUser(USERS.acmeHelpDesk, async (c) => {
      expect(await count(c, `select 1 from public.devices`)).toBeGreaterThan(0);
      expect(await count(c, `select 1 from public.security_events`)).toBeGreaterThan(0);
      expect(await count(c, `select 1 from public.incidents`)).toBe(0);
      expect(await count(c, `select 1 from public.audit_events`)).toBe(0);
      expect(await count(c, `select 1 from public.enrollment_tokens`)).toBe(0);
    });
  });
  it('analyst cannot see the tenant audit log or user directory', async () => {
    await asUser(USERS.acmeAnalyst, async (c) => {
      expect(await count(c, `select 1 from public.audit_events`)).toBe(0);
      expect(await count(c, `select 1 from public.organization_users where user_id <> $1`, [USERS.acmeAnalyst])).toBe(0);
    });
  });
  it('browser-history evidence requires tenant.incident.history.read', async () => {
    await asService((c) =>
      c.query(`insert into public.incident_artifacts (organization_id, incident_id, artifact_type, content)
               values ($1, '00000000-0000-4000-f500-000000000002', 'browser_history', '{"entries":[]}'),
                      ($1, '00000000-0000-4000-f500-000000000002', 'diagnostics', '{}')`, [ORG_ACME]),
    );
    await asUser(USERS.acmeSecAdmin, async (c) => {
      expect(await count(c, `select 1 from public.incident_artifacts where artifact_type = 'browser_history'`)).toBe(0);
      expect(await count(c, `select 1 from public.incident_artifacts where artifact_type = 'diagnostics'`)).toBeGreaterThan(0);
    });
    await asUser(USERS.acmeOwner, async (c) => {
      expect(await count(c, `select 1 from public.incident_artifacts where artifact_type = 'browser_history'`)).toBeGreaterThan(0);
    });
  });
});

describe('anonymous access', () => {
  it('anon can read nothing', async () => {
    for (const [table] of TENANT_TABLES) {
      await asUser(null, async (c) => {
        await expect(c.query(`select 1 from public.${table} limit 1`)).rejects.toThrow(/permission denied/);
      });
    }
  });
});

describe('platform users and tenant context', () => {
  it('without an entered context a platform super admin sees tenants but no tenant data', async () => {
    await asUser(USERS.platformSuperAdmin, async (c) => {
      expect(await count(c, `select 1 from public.organizations`)).toBeGreaterThanOrEqual(2);
      expect(await count(c, `select 1 from public.devices`)).toBe(0);
      expect(await count(c, `select 1 from public.policies`)).toBe(0);
      expect(await count(c, `select 1 from public.security_events`)).toBe(0);
    });
  });

  it('an entered context grants that tenant only, per platform role', async () => {
    const ctx = await asService(async (c) => {
      const r = await c.query<{ id: string }>(
        `insert into public.platform_tenant_contexts (actor_user_id, organization_id, platform_roles, expires_at)
         values ($1, $2, array['PlatformSecurityAdmin'], now() + interval '30 minutes') returning id`,
        [USERS.platformSecurityAdmin, ORG_ACME],
      );
      return r.rows[0]!.id;
    });
    try {
      await asUser(USERS.platformSecurityAdmin, async (c) => {
        expect(await count(c, `select 1 from public.devices where organization_id = $1`, [ORG_ACME])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.security_events where organization_id = $1`, [ORG_ACME])).toBeGreaterThan(0);
        expect(await count(c, `select 1 from public.devices where organization_id = $1`, [ORG_INTERNAL])).toBe(0);
        // Platform security admin's context role does not include history evidence.
        expect(await count(c, `select 1 from public.incident_artifacts where artifact_type = 'browser_history'`)).toBe(0);
      });
      // Another platform user does not inherit someone else's context.
      await asUser(USERS.platformSupport, async (c) => {
        expect(await count(c, `select 1 from public.devices`)).toBe(0);
      });
    } finally {
      await asService((c) => c.query(`update public.platform_tenant_contexts set ended_at = now() where id = $1`, [ctx]));
    }
    await asUser(USERS.platformSecurityAdmin, async (c) => {
      expect(await count(c, `select 1 from public.devices`)).toBe(0);
    });
  });

  it('expired contexts grant nothing', async () => {
    await asService((c) =>
      c.query(
        `insert into public.platform_tenant_contexts (actor_user_id, organization_id, platform_roles, started_at, expires_at)
         values ($1, $2, array['PlatformSupport'], now() - interval '2 hours', now() - interval '1 hour')`,
        [USERS.platformSupport, ORG_ACME],
      ),
    );
    await asUser(USERS.platformSupport, async (c) => {
      expect(await count(c, `select 1 from public.devices`)).toBe(0);
    });
    await asService((c) => c.query(`update public.platform_tenant_contexts set ended_at = now() where actor_user_id = $1 and ended_at is null`, [USERS.platformSupport]));
  });

  it('platform auditor reads cross-tenant audit but no tenant operational data', async () => {
    await asUser(USERS.platformAuditor, async (c) => {
      expect(await count(c, `select 1 from public.audit_events where organization_id = $1`, [ORG_ACME])).toBeGreaterThan(0);
      expect(await count(c, `select 1 from public.audit_events where organization_id = $1`, [ORG_INTERNAL])).toBeGreaterThan(0);
      expect(await count(c, `select 1 from public.devices`)).toBe(0);
    });
  });

  it('tenant users never see platform-only data', async () => {
    await asUser(USERS.acmeOwner, async (c) => {
      expect(await count(c, `select 1 from public.threat_indicators`)).toBe(0);
      expect(await count(c, `select 1 from public.platform_user_roles`)).toBe(0);
      expect(await count(c, `select 1 from public.audit_events where organization_id is null`)).toBe(0);
      const r = await c.query(`select public.has_platform_permission('platform.tenants.read') as p`);
      expect(r.rows[0].p).toBe(false);
    });
  });
});

describe('membership lifecycle', () => {
  it('disabled tenants and removed members lose access', async () => {
    await asService((c) => c.query(`update public.organizations set status = 'disabled' where id = $1`, [ORG_ACME]));
    try {
      await asUser(USERS.acmeOwner, async (c) => {
        expect(await count(c, `select 1 from public.devices`)).toBe(0);
      });
    } finally {
      await asService((c) => c.query(`update public.organizations set status = 'active' where id = $1`, [ORG_ACME]));
    }
    await asService((c) => c.query(`update public.organization_users set status = 'removed' where user_id = $1`, [USERS.acmeHelpDesk]));
    try {
      await asUser(USERS.acmeHelpDesk, async (c) => {
        expect(await count(c, `select 1 from public.devices`)).toBe(0);
      });
    } finally {
      await asService((c) => c.query(`update public.organization_users set status = 'active' where user_id = $1`, [USERS.acmeHelpDesk]));
    }
  });
});

describe('integrity triggers', () => {
  it('audit events are append-only, even for the service connection', async () => {
    await asService(async (c) => {
      await expect(c.query(`update public.audit_events set action = 'X'`)).rejects.toThrow(/append-only/);
      await expect(c.query(`delete from public.audit_events`)).rejects.toThrow(/append-only/);
      await expect(c.query(`truncate public.audit_events`)).rejects.toThrow(/append-only/);
    });
  });

  it('policy versions are immutable except published -> superseded', async () => {
    await asService(async (c) => {
      const v = await c.query<{ id: string }>(
        `insert into public.policy_versions (organization_id, policy_id, version_number, schema_version, rule_count, checksum, compiled_payload)
         values ($1, '00000000-0000-4000-f100-000000000002', 999, 1, 0, repeat('c', 64), '{}') returning id`,
        [ORG_ACME],
      );
      const id = v.rows[0]!.id;
      await expect(c.query(`update public.policy_versions set checksum = repeat('d', 64) where id = $1`, [id])).rejects.toThrow(/immutable/);
      await expect(c.query(`update public.policy_versions set compiled_payload = '{"x":1}' where id = $1`, [id])).rejects.toThrow(/immutable/);
      await expect(c.query(`delete from public.policy_versions where id = $1`, [id])).rejects.toThrow(/immutable/);
      await c.query(`update public.policy_versions set status = 'superseded' where id = $1`, [id]);
      await expect(c.query(`update public.policy_versions set status = 'published' where id = $1`, [id])).rejects.toThrow(/immutable/);
    });
  });

  it('cross-tenant references are rejected by composite foreign keys', async () => {
    await asService(async (c) => {
      await expect(
        c.query(`insert into public.security_events (organization_id, device_id, source_event_id, event_type, occurred_at)
                 values ($1, $2, gen_random_uuid(), 'URL_BLOCKED', now())`, [ORG_INTERNAL, ACME_DEVICE]),
      ).rejects.toThrow(/foreign key/);
      await expect(
        c.query(`insert into public.policy_rules (organization_id, policy_id, rule_type, normalized_value, normalized_hash)
                 values ($1, '00000000-0000-4000-f100-000000000002', 'BLOCK_DOMAIN', 'x.example', repeat('e', 64))`, [ORG_INTERNAL]),
      ).rejects.toThrow(/foreign key/);
    });
  });

  it('tenant roles cannot be granted platform permissions and platform roles cannot be tenant-assigned', async () => {
    await asService(async (c) => {
      await expect(
        c.query(`insert into public.role_permissions (role_id, permission_key)
                 select id, 'platform.tenants.manage' from public.roles where key = 'TenantOwner'`),
      ).rejects.toThrow(/tenant role cannot hold platform permission/);
      await expect(
        c.query(`insert into public.organization_user_roles (organization_id, user_id, role_id)
                 select $1, $2, id from public.roles where key = 'PlatformSuperAdmin'`, [ORG_ACME, USERS.acmeHelpDesk]),
      ).rejects.toThrow(/only reference tenant roles/);
    });
  });
});
