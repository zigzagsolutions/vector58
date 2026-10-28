import 'server-only';
import pg from 'pg';
import { serverEnv } from './env';

/**
 * Database access for trusted server code.
 *
 *  - withServiceTx: table-owner connection (RLS not applied). Only used AFTER
 *    an explicit authorization check, or for device-authenticated endpoints.
 *  - withUserTx: runs as the `authenticated` role with the user's JWT claims,
 *    exactly like PostgREST, so RLS applies as defence in depth for portal reads.
 */
export type Db = Pick<pg.PoolClient, 'query'>;

let pool: pg.Pool | undefined;

export function getPool(): pg.Pool {
  if (!pool) {
    const env = serverEnv();
    pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: env.DATABASE_POOL_MAX });
  }
  return pool;
}

export async function closePool(): Promise<void> {
  await pool?.end();
  pool = undefined;
}

async function tx<T>(
  setup: (c: pg.PoolClient) => Promise<void>,
  fn: (db: Db) => Promise<T>,
): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query('begin');
    await setup(client);
    const result = await fn(client);
    await client.query('commit');
    return result;
  } catch (e) {
    await client.query('rollback').catch(() => undefined);
    throw e;
  } finally {
    client.release();
  }
}

export function withServiceTx<T>(fn: (db: Db) => Promise<T>): Promise<T> {
  return tx(async () => undefined, fn);
}

export function withUserTx<T>(userId: string, fn: (db: Db) => Promise<T>): Promise<T> {
  return tx(async (c) => {
    await c.query('set local role authenticated');
    await c.query(`select set_config('request.jwt.claims', $1, true)`, [
      JSON.stringify({ sub: userId, role: 'authenticated' }),
    ]);
  }, fn);
}
