import 'server-only';
import { withServiceTx } from '../db';
import { expireStaleIndicators, syncThreatSource } from './threats';

/** Expire stale indicators, commands and tenant contexts (scheduled). */
export async function runMaintenance() {
  return withServiceTx(async (db) => {
    const indicators = await expireStaleIndicators(db);
    const commands = await db.query(
      `update public.endpoint_commands set status = 'EXPIRED' where status in ('PENDING', 'RECEIVED') and expires_at <= now()`,
    );
    const contexts = await db.query(
      `update public.platform_tenant_contexts set ended_at = expires_at where ended_at is null and expires_at <= now()`,
    );
    return { indicators, commands: commands.rowCount ?? 0, contexts: contexts.rowCount ?? 0 };
  });
}

/** Sync every enabled automated feed; failures are isolated per source. */
export async function syncAllFeeds() {
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
  return results;
}
