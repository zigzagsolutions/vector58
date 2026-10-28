import 'server-only';
import { z } from 'zod';

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  NEXT_PUBLIC_SUPABASE_URL: z.string().url().optional(),
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: z.string().optional(),
  NEXT_PUBLIC_APP_BASE_URL: z.string().url().default('http://localhost:3000'),
  SUPABASE_SECRET_KEY: z.string().optional(),
  TRUSTED_PROXY_MODE: z
    .string()
    .regex(/^(vercel|none|xff:\d{1,2})$/)
    .default(process.env.VERCEL ? 'vercel' : 'none'),
  CRON_SECRET: z.string().optional(),
  ALLOWED_ORIGINS: z.string().optional(),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(50).default(5),
});

export type ServerEnv = z.infer<typeof EnvSchema>;

let cached: ServerEnv | undefined;

/** Parsed lazily so `next build` works without runtime secrets present. */
export function serverEnv(): ServerEnv {
  if (!cached) {
    const parsed = EnvSchema.safeParse(process.env);
    if (!parsed.success) {
      throw new Error(
        `Invalid server environment: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
      );
    }
    cached = parsed.data;
  }
  return cached;
}

export function allowedOrigins(): string[] {
  const env = serverEnv();
  const list = (env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? list : [new URL(env.NEXT_PUBLIC_APP_BASE_URL).origin];
}
