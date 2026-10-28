import { ALL_ROLES } from '@bsp/auth-permissions';
import { afterAll, describe, expect, it } from 'vitest';
import { asService, closePool } from '../fixtures/db';

afterAll(closePool);

describe('database RBAC matches @bsp/auth-permissions', () => {
  it('role -> permission sets are identical', async () => {
    const rows = await asService((c) =>
      c.query<{ key: string; perms: string[] }>(
        `select r.key, coalesce(array_agg(rp.permission_key order by rp.permission_key) filter (where rp.permission_key is not null), '{}') as perms
         from public.roles r left join public.role_permissions rp on rp.role_id = r.id
         where r.organization_id is null group by r.key`,
      ),
    );
    const db = Object.fromEntries(rows.rows.map((r) => [r.key, [...r.perms].sort()]));
    const ts = Object.fromEntries(
      ALL_ROLES.map((r) => [
        r.key,
        [...(r.scope === 'platform' ? [...r.permissions, ...r.tenantContextPermissions] : r.permissions)].sort(),
      ]),
    );
    expect(db).toEqual(ts);
  });
});
