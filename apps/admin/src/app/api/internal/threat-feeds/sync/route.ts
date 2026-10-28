import { apiHandler, json } from '@/server/http';
import { requireCronSecret } from '@/server/internal-auth';
import { syncAllFeeds } from '@/server/services/maintenance';

export const dynamic = 'force-dynamic';
export const maxDuration = 300;

/** Sync every enabled automated feed. Called by the threat-feed-sync Edge Function / cron. */
export const POST = apiHandler(async (req: Request) => {
  requireCronSecret(req);
  return json({ results: await syncAllFeeds() });
});
