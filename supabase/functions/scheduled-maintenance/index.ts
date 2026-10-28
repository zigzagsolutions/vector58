// Expires stale threat indicators, endpoint commands and platform tenant
// contexts. Scheduled with pg_cron + pg_net (see docs/deployment.md).
import { forwardToApp } from '../_shared/forward.ts';

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('Method not allowed', { status: 405 });
  return forwardToApp('/api/internal/maintenance');
});
