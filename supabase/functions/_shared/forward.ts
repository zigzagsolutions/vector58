// Shared by the scheduled Edge Functions. They hold no business logic: they
// call the Next.js internal endpoints, which own the database work, with the
// CRON_SECRET shared secret. Secrets come from `supabase secrets set`, never
// from source control.

export async function forwardToApp(path: string): Promise<Response> {
  const base = Deno.env.get('APP_BASE_URL');
  const secret = Deno.env.get('CRON_SECRET');
  if (!base || !secret || secret.length < 32) {
    return Response.json(
      { error: 'APP_BASE_URL and CRON_SECRET (>= 32 chars) must be set as function secrets' },
      { status: 500 },
    );
  }
  const url = new URL(path, base);
  if (
    url.protocol !== 'https:' &&
    url.hostname !== 'localhost' &&
    url.hostname !== 'host.docker.internal'
  ) {
    return Response.json({ error: 'APP_BASE_URL must use https' }, { status: 500 });
  }
  const started = Date.now();
  const res = await fetch(url, {
    method: 'POST',
    headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json' },
    signal: AbortSignal.timeout(280_000),
  });
  const body = await res.text();
  console.log(JSON.stringify({ path, status: res.status, ms: Date.now() - started }));
  return new Response(body, {
    status: res.status,
    headers: { 'content-type': 'application/json' },
  });
}
