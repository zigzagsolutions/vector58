'use client';
import { createBrowserClient } from '@supabase/ssr';

/** Browser client: publishable key only. Used for sign-in; data access goes through server APIs. */
export const supabaseBrowser = () =>
  createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
  );
