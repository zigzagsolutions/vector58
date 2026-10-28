import { withServiceTx } from '@/server/db';
import { apiHandler, json } from '@/server/http';
import { requireCronSecret } from '@/server/internal-auth';
import { syncThreatSource } from '@/server/services/threats';

export const dynamic = 'force-dynamic';
export const maxDuration = 300;

/** Sync every enabled automated feed. Called by the threat-feed-sync Edge Function / cron. */
export const POST = apiHandler(async (req: Request) => {
  requireCronSecret(req);
  const sources = await withServiceTx((db) =>
    db.query<{ id: string; name: string }>(`select id, name from public.threat_sources where enabled and source_type <> 'manual'`),
  );
  const results: Record<string, unknown> = {};
  for (const s of sources.rows) {
    try {
      results[s.name] = await syncThreatSource({ kind: 'system' }, s.id);
    } catch (e) {
      results[s.name] = { error: (e as Error).message };
    }
  }
  return json({ results });
});
