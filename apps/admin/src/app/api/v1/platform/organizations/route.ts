import { platformCreateOrganization, platformListOrganizations } from '@/server/api/v1';
import { apiDeps } from '@/server/api/deps';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const GET = apiHandler((req: Request) => platformListOrganizations(req, apiDeps()));
export const POST = apiHandler((req: Request) => platformCreateOrganization(req, apiDeps()));
