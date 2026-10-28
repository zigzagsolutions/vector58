import { deviceCommands } from '@/server/api/v1';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const GET = apiHandler((req: Request) => deviceCommands(req));
