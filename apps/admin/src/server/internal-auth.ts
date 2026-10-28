import 'server-only';
import { timingSafeEqual } from 'node:crypto';
import { unauthenticated } from '@bsp/shared';
import { serverEnv } from './env';

/** Scheduled jobs (Supabase Edge Function / Vercel Cron) authenticate with CRON_SECRET. */
export function requireCronSecret(req: Request): void {
  const expected = serverEnv().CRON_SECRET;
  const got = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ?? '';
  if (!expected || expected.length < 32) throw unauthenticated('Scheduled jobs are not configured');
  const a = Buffer.from(got);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw unauthenticated();
}
