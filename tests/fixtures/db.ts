import pg from 'pg';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres@127.0.0.1:54329/bsp_test';

export const ORG_INTERNAL = '00000000-0000-4000-a000-000000000001';
export const ORG_ACME = '00000000-0000-4000-a000-000000000002';

export const USERS = {
  platformSuperAdmin: '00000000-0000-4000-b000-000000000001',
  platformSecurityAdmin: '00000000-0000-4000-b000-000000000002',
  platformSupport: '00000000-0000-4000-b000-000000000003',
  platformAuditor: '00000000-0000-4000-b000-000000000004',
  internalOwner: '00000000-0000-4000-c000-000000000001',
  internalSecAdmin: '00000000-0000-4000-c000-000000000002',
  internalAnalyst: '00000000-0000-4000-c000-000000000003',
  internalHelpDesk: '00000000-0000-4000-c000-000000000004',
  acmeOwner: '00000000-0000-4000-d000-000000000001',
  acmeSecAdmin: '00000000-0000-4000-d000-000000000002',
  acmeAnalyst: '00000000-0000-4000-d000-000000000003',
  acmeHelpDesk: '00000000-0000-4000-d000-000000000004',
  demoSecAdmin: '00000000-0000-4000-e000-000000000001',
} as const;

export const ACME_DEVICE = '00000000-0000-4000-f300-000000000002';

let pool: pg.Pool | undefined;
export function getPool(): pg.Pool {
  pool ??= new pg.Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  return pool;
}
export async function closePool() {
  await pool?.end();
  pool = undefined;
}

/** Run as the trusted server (table owner, RLS not applied). */
export async function asService<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await getPool().connect();
  try {
    return await fn(c);
  } finally {
    c.release();
  }
}

/**
 * Run exactly like a PostgREST request from a signed-in browser: role
 * `authenticated` with the user's JWT claims. Always rolled back.
 */
export async function asUser<T>(userId: string | null, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await getPool().connect();
  try {
    await c.query('begin');
    await c.query(`set local role ${userId ? 'authenticated' : 'anon'}`);
    await c.query(`select set_config('request.jwt.claims', $1, true)`, [
      JSON.stringify(userId ? { sub: userId, role: 'authenticated' } : { role: 'anon' }),
    ]);
    return await fn(c);
  } finally {
    await c.query('rollback').catch(() => undefined);
    c.release();
  }
}

export async function count(c: pg.PoolClient, sql: string, params: unknown[] = []): Promise<number> {
  const r = await c.query<{ n: string }>(`select count(*)::text as n from (${sql}) q`, params);
  return Number(r.rows[0]?.n ?? 0);
}
