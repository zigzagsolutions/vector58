import { orgCreateCommand } from '@/server/api/v1';
import { apiDeps } from '@/server/api/deps';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const POST = apiHandler((req: Request, ctx: { params: Promise<{ id: string }> }) => orgCreateCommand(req, ctx, apiDeps()));
