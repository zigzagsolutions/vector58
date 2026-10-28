import { withServiceTx } from '@/server/db';
import { apiHandler, json } from '@/server/http';
import { requireCronSecret } from '@/server/internal-auth';
import { expireStaleIndicators } from '@/server/services/threats';

export const dynamic = 'force-dynamic';

/** Expire stale indicators, commands and tenant contexts. Called on a schedule. */
export const POST = apiHandler(async (req: Request) => {
  requireCronSecret(req);
  const result = await withServiceTx(async (db) => {
    const indicators = await expireStaleIndicators(db);
    const commands = await db.query(
      `update public.endpoint_commands set status = 'EXPIRED' where status in ('PENDING', 'RECEIVED') and expires_at <= now()`,
    );
    const contexts = await db.query(
      `update public.platform_tenant_contexts set ended_at = expires_at where ended_at is null and expires_at <= now()`,
    );
    return { indicators, commands: commands.rowCount ?? 0, contexts: contexts.rowCount ?? 0 };
  });
  return json(result);
});
