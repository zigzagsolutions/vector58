import { apiHandler, json } from '@/server/http';
import { requireCronSecret } from '@/server/internal-auth';
import { runMaintenance } from '@/server/services/maintenance';

export const dynamic = 'force-dynamic';

/** Expire stale indicators, commands and tenant contexts. Called on a schedule. */
export const POST = apiHandler(async (req: Request) => {
  requireCronSecret(req);
  return json(await runMaintenance());
});
