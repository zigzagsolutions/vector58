import { json } from '@/server/http';
import { systemHealth } from '@/server/services/dashboard';

export const dynamic = 'force-dynamic';

/** Liveness/readiness probe. Reveals no tenant data. */
export async function GET() {
  const health = await systemHealth();
  return json({ status: health.database === 'ok' ? 'ok' : 'degraded', database: health.database, apiVersion: 'v1' }, {
    status: health.database === 'ok' ? 200 : 503,
  });
}
