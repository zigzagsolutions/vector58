# Phase 1 acceptance test

This is the end-to-end flow Phase 1 must support, with the exact steps. Steps 9 to 23 (the endpoint half) also run automatically on every CI build, on Linux with Chromium, in `tests/browser-e2e/full-stack.test.ts`. The steps that need a real Windows endpoint, Edge, or interactive sign-in are done by hand as written here.

Every seeded account's password is `Vector58-Dev!`.

## Environment

| #   | Step                                   | How                                                                                                                                                    | Expected                                                           |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| 1   | Clean Supabase development environment | `supabase start` (local) or a new hosted dev project linked with `supabase link`                                                                       | Empty project                                                      |
| 2   | Apply migrations                       | `supabase db reset` (local) or `supabase db push` (hosted)                                                                                             | Nine migrations applied, no errors                                 |
| 3   | Load seed data                         | Included in `supabase db reset`. Hosted: `psql "$DB_URL" -f supabase/seed.sql`                                                                         | Tenants _Internal Company_ and _Acme Corporation_, seeded users    |
| 4   | Start Next.js                          | `cp apps/admin/.env.example apps/admin/.env.local`, fill in the Supabase URL and publishable key, `DATABASE_URL`, and a `CRON_SECRET`; then `pnpm dev` | `http://localhost:3000/login` loads, `/api/v1/health` returns `ok` |

## Tenant setup

| #   | Step                            | How                                                                                             | Expected                                                            |
| --- | ------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| 5   | Sign in as Platform Super Admin | `platform.superadmin@vector58.test`                                                             | Lands on **Platform → Overview**                                    |
| 6   | Create a tenant                 | **Customers → New customer**: name `Demo Corp`, slug `demo-corp`                                | Tenant created with a default policy; `TENANT_CREATED` in **Audit** |
| 7   | Add a Tenant Security Admin     | **Customers → Demo Corp → Assign tenant user**: `new.secadmin@demo.test`, role _Security Admin_ | User listed under _Tenant users_; `TENANT_USER_ADDED` audited       |
| 8   | Sign in as the tenant admin     | Sign out, then sign in as `new.secadmin@demo.test`                                              | Lands on the Demo Corp dashboard. No platform navigation.           |

## Endpoint

| #   | Step                      | How                                                                                                                                                                                                                                                                                                                    | Expected                                                                                                      |
| --- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 9   | Enroll a Windows endpoint | **Settings → Enrollment tokens → Create** and copy the token. On the endpoint (elevated): `./install/build-agent.ps1`, then `./install/install-agent.ps1 -ApiBaseUrl <https url> -EnrollmentToken <token>`. For a local portal, expose it over https (for example with a tunnel) because the agent refuses plain http. | `verify-agent.ps1` passes; the enrollment token file is consumed                                              |
| 10  | Confirm heartbeat         | **Devices**                                                                                                                                                                                                                                                                                                            | The device appears with a recent _Last heartbeat_ and agent version 0.1.0                                     |
| 11  | Load the Chrome extension | `pnpm --filter @bsp/extension build`, then `chrome://extensions` → Developer mode → Load unpacked → `apps/extension/dist/chrome`                                                                                                                                                                                       | Extension ID `ikgimjohebonbmlfdngiiebaadojbdmp`                                                               |
| 12  | Load the Edge extension   | `edge://extensions` → Developer mode → Load unpacked → `apps/extension/dist/edge`                                                                                                                                                                                                                                      | Same dev ID                                                                                                   |
| 13  | Confirm native messaging  | Open each extension's popup. Check the device page in the portal.                                                                                                                                                                                                                                                      | Popup says _Agent connection: Connected_. The device page lists a Chrome and an Edge client marked connected. |

## Policy and blocking

| #   | Step                                  | How                                                                                                             | Expected                                                                                                                 |
| --- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 14  | Add the domain                        | **Policies → Default Policy → Add rule**: _Block domain_, `phase1-block-test.example`                           | Rule listed; `BLOCK_RULE_CREATED` audited                                                                                |
| 15  | Publish                               | **Publish** on the policy page                                                                                  | New version created; `POLICY_PUBLISHED` audited                                                                          |
| 16  | Version increments                    | Policy page version history                                                                                     | Version N+1 published; the previous version is marked _superseded_ and its content is unchanged                          |
| 17  | Agent receives it                     | Device page _Current policy version_ (or `BrowserSecurity.Agent.Service.exe status`)                            | Shows the new version within one heartbeat (60 s)                                                                        |
| 18  | Chrome applies it                     | Chrome popup, or the device page's browser table (_Applied policy_)                                             | Versions match                                                                                                           |
| 19  | Edge applies it                       | Edge popup, or the device page's browser table (_Applied policy_)                                               | Versions match                                                                                                           |
| 20  | Navigate to the blocked site          | Open `https://phase1-block-test.example/` (also try `https://www.phase1-block-test.example/x`) in both browsers |                                                                                                                          |
| 21  | Browser blocks access                 |                                                                                                                 | The **"This site has been blocked"** page shows the domain, the reason and the rule number. The site is never contacted. |
| 22  | `URL_BLOCKED` created                 | **Events**, type `URL_BLOCKED`                                                                                  | One event per browser, with device, browser, URL, rule and policy version                                                |
| 23  | Event appears in the tenant dashboard | Tenant **Overview**                                                                                             | _Blocked Events Today_ and the recent events list include it                                                             |

## Isolation and platform access

| #   | Step                                | How                                                                          | Expected                                                                                                         |
| --- | ----------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| 24  | Sign in as another tenant           | `secadmin@acme.test`                                                         | Acme dashboard                                                                                                   |
| 25  | Demo Corp data is inaccessible      | Paste a Demo Corp URL (`/o/<demoOrgId>/devices`, a device URL, a policy URL) | Not found. Acme lists show no Demo Corp device, policy or event. The API returns 404 for the other tenant's ids. |
| 26  | Sign in as Platform Security Admin  | `platform.security@vector58.test`                                            | Platform console; tenant pages are not reachable without context                                                 |
| 27  | Enter the original tenant's context | **Customers → Demo Corp → Enter tenant context** (reason required)           | Redirects into Demo Corp with a **"Viewing Tenant: Demo Corp"** banner and _Return to Platform_                  |
| 28  | Tenant data is visible              | Devices, Policies, Events                                                    | The device, policy and `URL_BLOCKED` events are visible (read and policy permissions only, per role)             |
| 29  | Cross-tenant access is audited      | **Platform → Audit** (and Demo Corp's own **Audit**)                         | `PLATFORM_ADMIN_ENTERED_TENANT` with the actor, tenant, reason and expiry; later `PLATFORM_ADMIN_EXITED_TENANT`  |

## Automated coverage

| Steps                                                       | Automated by                                                                                   |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| 2–3                                                         | `scripts/db-reset.sh` in `test:db` and `test:e2e` (vanilla Postgres plus a Supabase shim)      |
| 6–8, 24–29 (authorization, context, audit)                  | `tests/integration/api-flow.test.ts`, `tests/tenant-isolation/rls.test.ts`                     |
| 9–10, 13–23 (Chrome)                                        | `tests/browser-e2e/full-stack.test.ts`: real Next server, .NET agent and native host, Chromium |
| Windows service install, DPAPI, Edge, Supabase Auth sign-in | Manual, as above                                                                               |
