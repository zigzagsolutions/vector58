import 'server-only';
import { AppError, isAppError, type AppErrorCode } from '@bsp/shared';
import type { z } from 'zod';
import { allowedOrigins, serverEnv } from './env';

const STATUS: Record<AppErrorCode, number> = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  VALIDATION_FAILED: 400,
  CONFLICT: 409,
  TENANT_DISABLED: 403,
  RATE_LIMITED: 429,
  INTERNAL: 500,
};

export const API_VERSION = 'v1';

export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('x-api-version', API_VERSION);
  headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function errorResponse(e: unknown): Response {
  if (isAppError(e)) {
    return json(
      { error: { code: e.code, message: e.message, details: e.details ?? undefined }, apiVersion: API_VERSION },
      { status: STATUS[e.code] },
    );
  }
  console.error(JSON.stringify({ level: 'error', msg: 'unhandled_api_error', error: String(e), stack: (e as Error)?.stack }));
  return json({ error: { code: 'INTERNAL', message: 'Internal server error' }, apiVersion: API_VERSION }, { status: 500 });
}

/** Wrap a handler so every thrown error becomes a versioned error envelope. */
export function apiHandler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (e) {
      return errorResponse(e);
    }
  };
}

export async function parseJson<S extends z.ZodType>(req: Request, schema: S): Promise<z.infer<S>> {
  const type = req.headers.get('content-type') ?? '';
  if (!type.toLowerCase().startsWith('application/json')) {
    throw new AppError('VALIDATION_FAILED', 'Content-Type must be application/json');
  }
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new AppError('VALIDATION_FAILED', 'Request body is not valid JSON');
  }
  return parseWith(schema, body);
}

export function parseWith<S extends z.ZodType>(schema: S, value: unknown): z.infer<S> {
  const r = schema.safeParse(value);
  if (!r.success) {
    throw new AppError(
      'VALIDATION_FAILED',
      'Request validation failed',
      r.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    );
  }
  return r.data;
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^[0-9a-f:.]{2,45}$/i;
const isIp = (s: string) => IPV4.test(s) || (s.includes(':') && IPV6.test(s));

/**
 * Determine the caller's public IP from proxy headers according to the
 * configured trust model. Client-supplied IPs in request bodies are never used.
 */
export function clientIp(headers: Headers, mode = serverEnv().TRUSTED_PROXY_MODE): string | null {
  if (mode === 'none') return null;
  const xff = (headers.get('x-forwarded-for') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  let candidate: string | undefined;
  if (mode === 'vercel') {
    // Vercel's edge overwrites these headers; client-provided values are not forwarded.
    candidate = headers.get('x-real-ip') ?? xff[0];
  } else {
    const hops = Number(mode.slice(4));
    candidate = xff[xff.length - hops];
  }
  return candidate && isIp(candidate) ? candidate : null;
}

/**
 * CSRF defence for cookie-authenticated mutations: require an allowed Origin.
 * Bearer-token API clients are not subject to CSRF and skip this check.
 */
export function assertSameOrigin(req: Request): void {
  if (req.headers.get('authorization')) return;
  const origin = req.headers.get('origin');
  if (!origin || !allowedOrigins().includes(origin)) {
    throw new AppError('FORBIDDEN', 'Cross-origin request rejected');
  }
}

export function requestMeta(req: Request | { headers: Headers }) {
  return {
    ip: clientIp(req.headers),
    userAgent: req.headers.get('user-agent')?.slice(0, 512) ?? null,
  };
}
export type RequestMeta = ReturnType<typeof requestMeta>;
