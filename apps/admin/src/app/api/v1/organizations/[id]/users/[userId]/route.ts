import { orgChangeUserRole, orgRemoveUser } from '@/server/api/v1';
import { apiDeps } from '@/server/api/deps';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const PATCH = apiHandler((req: Request, ctx: { params: Promise<{ id: string; userId: string }> }) => orgChangeUserRole(req, ctx, apiDeps()));
export const DELETE = apiHandler((req: Request, ctx: { params: Promise<{ id: string; userId: string }> }) => orgRemoveUser(req, ctx, apiDeps()));
