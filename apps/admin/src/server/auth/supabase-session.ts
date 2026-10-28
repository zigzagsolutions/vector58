import 'server-only';
import { createServerClient } from '@supabase/ssr';
import { cookies, headers } from 'next/headers';
import type { SessionProvider, SessionUser } from './types';

function supabaseConfig() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) throw new Error('Supabase URL / publishable key are not configured');
  return { url, key };
}

export async function createSupabaseServerClient() {
  const { url, key } = supabaseConfig();
  const store = await cookies();
  return createServerClient(url, key, {
    cookies: {
      getAll: () => store.getAll(),
      setAll: (toSet) => {
        try {
          for (const c of toSet) store.set(c.name, c.value, c.options);
        } catch {
          // Called from a Server Component: cookies are refreshed by src/proxy.ts instead.
        }
      },
    },
  });
}

/**
 * Validates the session with Supabase Auth (`getUser` hits the Auth server,
 * unlike `getSession`, so a forged cookie cannot pass). API clients may send
 * `Authorization: Bearer <access token>` instead of cookies.
 */
export const supabaseSessionProvider: SessionProvider = {
  async getUser(): Promise<SessionUser | null> {
    const supabase = await createSupabaseServerClient();
    const auth = (await headers()).get('authorization');
    const bearer = auth?.match(/^Bearer\s+(.+)$/i)?.[1];
    const { data, error } = bearer ? await supabase.auth.getUser(bearer) : await supabase.auth.getUser();
    if (error || !data.user) return null;
    return { id: data.user.id, email: data.user.email ?? null };
  },
};
