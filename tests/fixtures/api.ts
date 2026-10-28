import { Authorizer, type SessionUser } from '@/server/auth/authorizer-export';
import type { ApiDeps } from '@/server/api/v1';
import { existingUsersOnlyDirectory } from '@/server/services/identity';

export const ORIGIN = 'http://localhost:3000';

/** API dependencies with a fixed signed-in user (null = anonymous). */
export function depsFor(user: SessionUser | string | null): ApiDeps {
  const u = typeof user === 'string' ? { id: user, email: null } : user;
  return {
    authorizer: new Authorizer({ getUser: async () => u }),
    identity: existingUsersOnlyDirectory,
  };
}

export function req(
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: {
      origin: ORIGIN,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

export async function body<T = Record<string, unknown>>(res: Response): Promise<T> {
  const text = await res.text();
  return (text ? JSON.parse(text) : {}) as T;
}
