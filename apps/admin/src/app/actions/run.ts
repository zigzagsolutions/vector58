import 'server-only';
import { isAppError } from '@bsp/shared';
import { headers } from 'next/headers';
import { requestMeta, type RequestMeta } from '@/server/http';
import type { ActionState } from './state';

/** Server-action wrapper: converts typed errors to form state; never leaks internals. */
export async function runAction(
  fn: (meta: RequestMeta) => Promise<ActionState>,
): Promise<ActionState> {
  try {
    return await fn(requestMeta({ headers: await headers() }));
  } catch (e) {
    if (isAppError(e)) {
      const details = Array.isArray(e.details)
        ? e.details
            .map((d: { path?: string; message?: string }) => `${d.path}: ${d.message}`)
            .join('; ')
        : '';
      return { ok: false, error: details ? `${e.message} (${details})` : e.message };
    }
    // Next.js navigation errors (redirect/notFound) must propagate.
    if (e && typeof e === 'object' && 'digest' in e) throw e;
    console.error(
      JSON.stringify({ level: 'error', msg: 'server_action_failed', error: String(e) }),
    );
    return { ok: false, error: 'Unexpected error. Please try again.' };
  }
}

export const str = (f: FormData, k: string) => {
  const v = f.get(k);
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
};
