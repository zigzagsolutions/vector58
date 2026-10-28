import { deviceEnroll } from '@/server/api/v1';
import { apiHandler } from '@/server/http';

export const dynamic = 'force-dynamic';
export const POST = apiHandler((req: Request) => deviceEnroll(req));
