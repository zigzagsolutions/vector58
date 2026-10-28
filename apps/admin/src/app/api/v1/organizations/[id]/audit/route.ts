import { orgAudit } from '@/server/api/v1';
import { apiDeps } from '@/server/api/deps';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const GET = apiHandler((req: Request, ctx: { params: Promise<{ id: string }> }) =>
  orgAudit(req, ctx, apiDeps()),
);
