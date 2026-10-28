import { orgDeleteRule } from '@/server/api/v1';
import { apiDeps } from '@/server/api/deps';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const DELETE = apiHandler(
  (req: Request, ctx: { params: Promise<{ id: string; ruleId: string }> }) =>
    orgDeleteRule(req, ctx, apiDeps()),
);
