# Deployment

Production runs Supabase (database, auth, functions) plus Vercel (portal and API). Endpoints only need outbound HTTPS to the Vercel URL.

## 1. Supabase

1. **Create a project.** Keep the region close to your Vercel functions region.
2. **Apply migrations:**
   ```bash
   supabase link --project-ref <ref>
   supabase db push            # applies supabase/migrations in order
   ```
   Never load `seed.sql` into production. It contains well-known passwords and enrollment tokens.
3. **Auth settings:** turn off _Allow new users to sign up_. Set _Site URL_ to `https://<app>` and add `https://<app>/auth/callback` to the redirect URLs. Configure SMTP for invitations. Turn on leaked-password protection and MFA as your policy requires.
4. **First platform admin:** invite the user (Authentication → Users → Invite), then grant the role in the SQL editor:
   ```sql
   insert into public.platform_user_roles (user_id, role_id)
   select u.id, r.id from auth.users u, public.roles r
   where u.email = 'you@yourcompany.com' and r.key = 'PlatformSuperAdmin';
   ```
   Everything after that, including your own company as Tenant #1, happens in the portal.
5. **Connection string for Vercel:** use the Supavisor **transaction pooler** URL (port 6543) with `?sslmode=require`, as `DATABASE_URL`. It connects as `postgres`; server code drops to `authenticated` for user-scoped reads.
6. **Edge Functions (scheduled jobs):**
   ```bash
   supabase secrets set APP_BASE_URL=https://<app> CRON_SECRET=<same 32+ char value as Vercel>
   supabase functions deploy scheduled-maintenance
   supabase functions deploy threat-feed-sync
   ```
   Schedule them with `pg_cron` and `pg_net` (Database → Extensions → enable both). Store the service key in Vault rather than inline:
   ```sql
   select vault.create_secret('<service-role-or-publishable-jwt>', 'functions_auth');
   select cron.schedule('bsp-maintenance', '*/15 * * * *', $$
     select net.http_post(
       url := 'https://<ref>.supabase.co/functions/v1/scheduled-maintenance',
       headers := jsonb_build_object('Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'functions_auth')));
   $$);
   select cron.schedule('bsp-feed-sync', '0 */6 * * *', $$
     select net.http_post(
       url := 'https://<ref>.supabase.co/functions/v1/threat-feed-sync',
       headers := jsonb_build_object('Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'functions_auth')));
   $$);
   ```
   Alternatively use Vercel Cron (below). Do not run both.

## 2. Vercel

1. **New Project → Import** the repository. Set **Root Directory** to `apps/admin`. The framework preset is Next.js. `apps/admin/vercel.json` sets `pnpm install --frozen-lockfile` and `pnpm --filter @bsp/admin build`. Keep "Include files outside the root directory" on (the default) so workspace packages are available.
2. **Environment variables** (Production and Preview):

   | Name                                   | Value                                             |
   | -------------------------------------- | ------------------------------------------------- |
   | `NEXT_PUBLIC_SUPABASE_URL`             | `https://<ref>.supabase.co`                       |
   | `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | project publishable (anon) key                    |
   | `NEXT_PUBLIC_APP_BASE_URL`             | `https://<app>`                                   |
   | `DATABASE_URL`                         | pooler URL with `sslmode=require` (**sensitive**) |
   | `SUPABASE_SECRET_KEY`                  | optional, for invitations (**sensitive**)         |
   | `TRUSTED_PROXY_MODE`                   | `vercel`                                          |
   | `CRON_SECRET`                          | 32+ random characters (**sensitive**)             |

   Preview deployments should point at a separate Supabase project or branch, never production data.

3. **Deploy**, then check:
   - `GET https://<app>/api/v1/health` returns `{"status":"ok"}`
   - `/login` works for the invited platform admin
   - `curl -X POST -H "Authorization: Bearer $CRON_SECRET" https://<app>/api/internal/maintenance` returns 200
4. **Cron:** `vercel.json` schedules `/api/internal/maintenance` (every 15 minutes) and `/api/internal/threat-feeds/sync` (every 6 hours). Vercel sends `Authorization: Bearer $CRON_SECRET` automatically. Sub-daily schedules need the Pro plan. On Hobby, delete the `crons` block and use the Supabase schedule.
5. **Custom domain:** add it in Vercel, then update `NEXT_PUBLIC_APP_BASE_URL`, the Supabase Site URL, and the agents' `ApiBaseUrl`. Agents refuse to send credentials to a URL other than the one they enrolled with, so plan this before rolling out widely, or re-enroll afterwards.

## 3. Endpoints

1. Build and sign the agent (`services/windows-agent/install/build-agent.ps1`, or the `windows-agent` CI artifact).
2. Publish the extension to the Chrome Web Store and Edge Add-ons. Record both IDs.
3. Per tenant: create an enrollment token in **Settings** with a sensible max-uses and expiry.
4. Deploy with Intune, GPO or another tool: `install-agent.ps1 -ApiBaseUrl https://<app> -EnrollmentToken <token> -ExtensionIds <chrome-id>,<edge-id>`, plus force-install policies. See [browser-extension.md](browser-extension.md).

## 4. Database changes

- Add a new file in `supabase/migrations`. Never edit one that has been applied.
- RBAC catalog changes: edit `packages/auth-permissions`. For changes after go-live, emit a **new** migration from the generator rather than editing `…09`.
- CI applies all migrations to a fresh Postgres on every run (`test:db`, `test:e2e`).

## 5. Operations checklist

- Rotate `CRON_SECRET` in Vercel and Supabase together.
- Monitor `/platform/health`, which shows offline devices, outdated policies and feed status.
- Back up with Supabase PITR. The audit log is append-only; export it periodically for long-term retention.
- Disabling a tenant (**Customers → tenant → Disable**) blocks its users and devices at once. Its devices keep enforcing their last policy.
