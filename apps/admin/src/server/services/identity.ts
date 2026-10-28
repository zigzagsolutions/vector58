import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { AppError } from '@bsp/shared';
import type { Db } from '../db';
import { serverEnv } from '../env';

/** Looks up or provisions user identities. Abstracted for SSO/SCIM (Entra ID, Okta) later. */
export interface IdentityDirectory {
  findOrInviteUser(db: Db, email: string): Promise<string>;
}

async function findByEmail(db: Db, email: string): Promise<string | null> {
  const r = await db.query<{ id: string }>(
    `select id from public.profiles where lower(email) = lower($1)`,
    [email],
  );
  return r.rows[0]?.id ?? null;
}

/** Directory that only resolves existing users (tests, and deployments without a secret key). */
export const existingUsersOnlyDirectory: IdentityDirectory = {
  async findOrInviteUser(db, email) {
    const id = await findByEmail(db, email);
    if (!id) {
      throw new AppError(
        'NOT_FOUND',
        `No account exists for ${email}. Ask them to sign up first, or configure invitations.`,
      );
    }
    return id;
  },
};

/** Uses the Supabase Auth admin API (server-only secret key) to invite unknown users. */
export function supabaseIdentityDirectory(): IdentityDirectory {
  const env = serverEnv();
  if (!env.SUPABASE_SECRET_KEY || !env.NEXT_PUBLIC_SUPABASE_URL) return existingUsersOnlyDirectory;
  const admin = createClient(env.NEXT_PUBLIC_SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return {
    async findOrInviteUser(db, email) {
      const existing = await findByEmail(db, email);
      if (existing) return existing;
      const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
        redirectTo: `${env.NEXT_PUBLIC_APP_BASE_URL}/login`,
      });
      if (error || !data.user)
        throw new AppError(
          'INTERNAL',
          `Could not invite ${email}: ${error?.message ?? 'unknown error'}`,
        );
      // The auth trigger creates the profile in the auth transaction; ensure it exists for ours.
      await db.query(
        `insert into public.profiles (id, email) values ($1, $2) on conflict (id) do nothing`,
        [data.user.id, email],
      );
      return data.user.id;
    },
  };
}
