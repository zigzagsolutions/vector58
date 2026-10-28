import { apiHandler, json } from '@/server/http';
import { requireCronSecret } from '@/server/internal-auth';
import { runMaintenance } from '@/server/services/maintenance';

export const dynamic = 'force-dynamic';

/** Expire stale indicators, commands and tenant contexts. Called on a schedule. */
const handler = apiHandler(async (req: Request) => {
  requireCronSecret(req);
  return json(await runMaintenance());
});

// POST for Supabase Edge Functions / manual runs; GET for Vercel Cron (which sends the same Bearer CRON_SECRET).
export const POST = handler;
export const GET = handler;
