# Vector58 Browser Security Platform

Multi-tenant enterprise browser security. Customer organizations (tenants) enroll Windows endpoints, publish block and allow policies, and see what was blocked. Vector58's own company is Tenant #1, with no special casing.

Phase 1 delivers the full loop: a tenant admin blocks a domain in the portal and publishes a policy. The Windows agent pulls and verifies it, then hands it to the Chrome and Edge extension over native messaging. The extension enforces it with `declarativeNetRequest`. The blocked navigation becomes a `URL_BLOCKED` event in that tenant's console, and no other tenant can see it.

---

## Contents

- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Local development](#local-development)
- [Supabase setup](#supabase-setup)
- [Vercel setup](#vercel-setup)
- [Environment variables](#environment-variables)
- [Database migrations and seed data](#database-migrations-and-seed-data)
- [Authentication, tenant, role and permission model](#authentication-tenant-role-and-permission-model)
- [Run the admin app](#run-the-admin-app)
- [Build the Chrome and Edge extensions](#build-the-chrome-and-edge-extensions)
- [Configure native messaging](#configure-native-messaging)
- [Build the Windows agent](#build-the-windows-agent)
- [Enroll an endpoint](#enroll-an-endpoint)
- [Create a blocked domain, publish, verify blocking](#create-a-blocked-domain-publish-and-verify-blocking)
- [Inspect a security event](#inspect-a-security-event)
- [Run the tests](#run-the-tests)
- [End-to-end acceptance test](#end-to-end-acceptance-test)
- [Troubleshooting](#troubleshooting)
- [Security considerations](#security-considerations)
- [Known Phase 1 limitations](#known-phase-1-limitations)
- [Phase 2 roadmap](#phase-2-roadmap)

---

## Architecture

```
                     ┌──────────────────────── Vercel ────────────────────────┐
  Admins (browser) ─▶│ Next.js admin portal + /api/v1                          │
   Supabase Auth     │  • server-side authorization (Authorizer → SQL funcs)   │
   session cookie    │  • policy compiler (@bsp/policy-engine)                 │
                     │  • /api/internal/* (cron: maintenance, feed sync)       │
                     └───────────────┬─────────────────────────▲───────────────┘
                                     │ pg (server-only)        │ HTTPS, "Authorization: Device <id>.<secret>"
                     ┌───────────────▼──────────┐              │
                     │ Supabase                  │              │
                     │  Postgres + RLS (every    │              │
                     │  table), Auth, Edge Fns   │              │
                     └───────────────────────────┘              │
                                                                │
  ┌──────────────────────────── Windows endpoint ───────────────┴───────────────────────┐
  │  BrowserSecurity.Agent.Service (LocalSystem)                                         │
  │   enroll → heartbeat → pull policy → verify checksum → cache (last-known-good)        │
  │   commands, durable event queue, DPAPI device secret                                  │
  │        ▲ named pipe (ACL: users connect, cannot create)        ▲ status pipe          │
  │        │                                                        │                     │
  │  BrowserSecurity.NativeHost.exe  ◀── stdio (native messaging) ──┐   BrowserSecurity.Tray│
  │        ▲                                                        │   (status only)       │
  │  Chrome / Edge MV3 extension: verify → DNR dynamic rules → blocked.html → URL_BLOCKED   │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

The design in detail: [docs/architecture.md](docs/architecture.md).

## Technology stack

| Area                 | Technology                                                                                               |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| Admin portal and API | Next.js 16 (App Router, `proxy.ts`), React 19, TypeScript 6, Tailwind CSS 4                              |
| Validation           | Zod 4 schemas in `@bsp/policy-types`, shared by server and extension                                     |
| Data                 | Supabase Postgres with row-level security on every table, Supabase Auth, Edge Functions (Deno)           |
| Server data access   | `pg` over a server-only `DATABASE_URL`; user reads run as `authenticated` with JWT claims so RLS applies |
| Browser enforcement  | Manifest V3 extension (one codebase for Chrome and Edge), `declarativeNetRequest` dynamic rules          |
| Endpoint             | .NET 10: Windows Service (Generic Host), WinForms tray, console native messaging host                    |
| Monorepo             | pnpm workspaces and Turborepo                                                                            |
| Tests                | Vitest, Playwright (Chromium), xUnit, GitHub Actions                                                     |
| Hosting              | Vercel (portal/API), Supabase (database/auth/functions)                                                  |

## Repository layout

```
apps/
  admin/                    Next.js portal + /api/v1 + /api/internal (Vercel project root)
  extension/                MV3 extension for Chrome and Edge (esbuild → dist/chrome, dist/edge)
packages/
  shared/                   errors, canonical JSON, hashing, protocol constants
  url-normalizer/           URL/domain normalization and matching
  auth-permissions/         permission + role catalog (source of truth for RBAC)
  policy-types/             Zod schemas: entities, API contracts, policy payload, native messages
  policy-engine/            deterministic compiler, precedence, rule ids, checksum
services/windows-agent/
  BrowserSecurity.Agent.sln
  src/BrowserSecurity.Agent.Shared         canonical JSON, policy validation, framing, models
  src/BrowserSecurity.Agent.Service        Windows service
  src/BrowserSecurity.Agent.NativeMessaging native messaging host (BrowserSecurity.NativeHost.exe)
  src/BrowserSecurity.Agent.Tray           tray status app
  tests/BrowserSecurity.Agent.Tests        xUnit (incl. TypeScript parity vectors)
  install/                                 PowerShell build/install/verify/uninstall scripts
supabase/
  migrations/               all schema, RLS, functions, RBAC reference data
  seed.sql                  development tenants, users, tokens, sample data
  functions/                scheduled Edge Functions (maintenance, threat-feed sync)
  config.toml               local Supabase CLI config
tests/
  tenant-isolation/         RLS tests against real Postgres
  integration/              API flow tests (same handlers as the routes)
  browser-e2e/              full-stack E2E (Next + Postgres + .NET agent + host + Chromium)
  unit/                     repo-level checks (generated files, secrets scan, seed ids)
scripts/                    local Postgres, db reset, code generators
docs/                       architecture and operations documentation
.github/workflows/ci.yml    CI
```

## Prerequisites

- Node.js 22.12 or later, and pnpm 10 (`corepack enable`)
- Supabase CLI with Docker for a full local stack, **or** PostgreSQL 16 for the database-only test setup
- .NET 10 SDK (agent). You can build and test on Linux or macOS, but the service, tray and DPAPI only run on Windows 10/11 or Server 2019+.
- PowerShell 7 for the agent scripts
- Chrome 120+ and/or Edge 120+

## Local development

```bash
pnpm install
cp apps/admin/.env.example apps/admin/.env.local    # fill in values, see below

# Option A: full local Supabase (Auth, Studio, Postgres). Needs Docker.
supabase start            # prints the API URL and publishable key
supabase db reset         # applies supabase/migrations and supabase/seed.sql

# Option B: database only (tests, API work without login)
pnpm db:local             # Postgres on 127.0.0.1:54329
pnpm db:reset             # shim + migrations + seed into bsp_dev

pnpm dev                  # http://localhost:3000
```

## Supabase setup

1. Create a Supabase project. Pick the region closest to your Vercel region.
2. Apply the schema from the repository: `supabase link --project-ref <ref>` then `supabase db push`. On a development project only, load the seed with `psql "$DB_URL" -f supabase/seed.sql`. The seed contains well-known passwords and tokens, so never load it into production.
3. Under **Authentication → Providers**, keep email enabled, turn **off** "Allow new users to sign up", and set the Site URL to your Vercel URL. Users are invited.
4. Set the Edge Function secrets and deploy the functions:
   `supabase secrets set APP_BASE_URL=https://<app> CRON_SECRET=<32+ random chars>`, then `supabase functions deploy scheduled-maintenance threat-feed-sync`.
5. Schedule them with `pg_cron` and `pg_net`, or use Vercel Cron instead. Both are described in [docs/deployment.md](docs/deployment.md).

## Vercel setup

1. Import the repository and set **Root Directory** to `apps/admin`. `vercel.json` sets the install and build commands for the pnpm workspace.
2. Add the [environment variables](#environment-variables) for Production and Preview. Use the Supavisor **transaction pooler** URL with `sslmode=require` for `DATABASE_URL`.
3. Set `TRUSTED_PROXY_MODE=vercel` so the server records endpoint public IPs from Vercel's edge headers.
4. Deploy. Check `GET /api/v1/health` and sign in.
5. `vercel.json` defines crons for `/api/internal/maintenance` (every 15 minutes) and `/api/internal/threat-feeds/sync` (every 6 hours). Sub-daily crons need a Pro plan; otherwise use the Supabase schedule.

## Environment variables

Admin app (`apps/admin/.env.example`). Only `NEXT_PUBLIC_*` reach the browser.

| Variable                               | Required | Purpose                                                                     |
| -------------------------------------- | -------- | --------------------------------------------------------------------------- |
| `NEXT_PUBLIC_SUPABASE_URL`             | yes      | Supabase API URL (auth)                                                     |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | yes      | Publishable (anon) key. Browser roles can only SELECT under RLS.            |
| `NEXT_PUBLIC_APP_BASE_URL`             | yes      | Public URL, used for links and the same-origin check                        |
| `DATABASE_URL`                         | yes      | **Server-only** Postgres URL used by trusted API code                       |
| `SUPABASE_SECRET_KEY`                  | no       | **Server-only**. Used only to send invites through the Auth admin API.      |
| `TRUSTED_PROXY_MODE`                   | yes      | `vercel`, `xff:<n>`, or `none`: how the server derives a client's public IP |
| `CRON_SECRET`                          | yes      | 32+ chars. Authenticates `/api/internal/*` callers.                         |
| `ALLOWED_ORIGINS`                      | no       | Extra origins allowed to make cookie-authenticated mutations                |

Agent (`appsettings.json`, then `%ProgramData%\Vector58\BrowserSecurity\agentsettings.json` written by the installer, then `BSP_Agent__*` environment variables): `ApiBaseUrl` (https only), `PortalUrl`, `AllowedExtensionIds`, and the poll intervals. The details are in [docs/windows-agent.md](docs/windows-agent.md).

Edge Functions: `APP_BASE_URL`, `CRON_SECRET`.

## Database migrations and seed data

Every schema object lives in `supabase/migrations`, applied in order:

| Migration                     | Contents                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| `…01_foundation`              | extensions, `app_private` schema, trigger helpers                                                     |
| `…02_identity_and_rbac`       | profiles, organizations, permissions, roles, memberships, platform tenant contexts, enrollment tokens |
| `…03_endpoints`               | devices, browser clients, release catalogs                                                            |
| `…04_threat_intel`            | threat sources, indicators, observations (append-only), allow lists                                   |
| `…05_policy`                  | policies, rules, immutable policy versions                                                            |
| `…06_events_incidents_audit`  | security events, incidents, commands, artifacts, append-only audit log                                |
| `…07_authorization_functions` | `permitted_organization_ids`, `has_tenant_permission`, …                                              |
| `…08_row_level_security`      | RLS on every table, grants, column-level hiding of secrets                                            |
| `…09_rbac_reference_data`     | **generated** from `@bsp/auth-permissions` (`pnpm tsx scripts/generate-rbac-sql.ts`)                  |

Never edit a migration that has been applied to production. Add a new one.

**Seed data** (`supabase/seed.sql`, development only). Every account's password is `Vector58-Dev!`.

| Account                                                  | Role                                            |
| -------------------------------------------------------- | ----------------------------------------------- |
| `platform.superadmin@vector58.test`                      | Platform Super Admin                            |
| `platform.security@vector58.test`                        | Platform Security Admin                         |
| `platform.support@vector58.test`                         | Platform Support                                |
| `platform.auditor@vector58.test`                         | Platform Auditor                                |
| `owner@ / secadmin@ / analyst@ / helpdesk@internal.test` | Internal Company (Tenant #1) roles              |
| `owner@ / secadmin@ / analyst@ / helpdesk@acme.test`     | Acme Corporation roles                          |
| `new.secadmin@demo.test`                                 | not assigned anywhere (for the acceptance demo) |

The seed also creates the enrollment tokens `dev-internal-enroll-token-0000000001` (Internal) and `dev-acme-enroll-token-00000000000001` (Acme), a default policy per tenant, an Acme-only rule (`acme-only-block.example`), sample global indicators (`global-malware-test.example`, `global-phish-test.example`), a platform safe list, and one Acme device, event and incident.

## Authentication, tenant, role and permission model

- **Authentication.** Supabase Auth with email and password. Signup is invite-only. The session cookie is refreshed in `proxy.ts`. Endpoints never use user sessions: they authenticate with a device credential issued at enrollment.
- **Tenants.** `organizations` rows. Every tenant-owned row carries `organization_id`, and composite foreign keys stop a row from referencing another tenant's data. The server always derives the tenant from the authenticated user or the device record, never from a client-supplied value.
- **Roles.** Platform roles (Super Admin, Security Admin, Support, Auditor) and tenant roles (Owner, Security Admin, Security Analyst, Help Desk). There is no `isAdmin` flag, and a lint rule rejects one.
- **Permissions.** Every check is against a named permission (`tenant.policy.publish`, `platform.support.enter_tenant`, and so on), defined in `packages/auth-permissions` and generated into the database. A user can assign only roles whose permissions they already hold.
- **Platform access to tenants.** Platform staff are never tenant members. To work inside a tenant they _enter tenant context_: a time-boxed (60 minute), audited row in `platform_tenant_contexts` that grants only their role's `tenantContextPermissions`. The UI shows a "Viewing Tenant" banner. There is no impersonation. Even Super Admins cannot read browser-history evidence.

The full matrix is in [docs/security-model.md](docs/security-model.md). Isolation tests are in [docs/tenant-isolation.md](docs/tenant-isolation.md).

## Run the admin app

```bash
pnpm dev                                   # development
pnpm --filter @bsp/admin build && pnpm --filter @bsp/admin start   # production build
```

Sign in at `/login`. Platform users land on `/platform`, tenant users on `/o/<orgId>`.

## Build the Chrome and Edge extensions

```bash
pnpm --filter @bsp/extension build         # dist/chrome and dist/edge (dev key → stable ID)
pnpm --filter @bsp/extension build -- --release   # store builds, no "key"
```

- **Chrome:** go to `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and pick `apps/extension/dist/chrome`.
- **Edge:** go to `edge://extensions`, turn on **Developer mode**, click **Load unpacked**, and pick `apps/extension/dist/edge`.

Development builds always get the ID `ikgimjohebonbmlfdngiiebaadojbdmp`. Store builds get IDs from each store, and Chrome and Edge IDs differ. ID handling and enterprise force-install are covered in [docs/browser-extension.md](docs/browser-extension.md).

## Configure native messaging

`install-agent.ps1` does all of this. Nothing needs editing by hand. It writes `com.vector58.browser_security.json` next to `BrowserSecurity.NativeHost.exe`, with `allowed_origins` for your extension IDs, and registers it under:

- `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vector58.browser_security`
- `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.vector58.browser_security`

The protocol is described in [docs/native-messaging.md](docs/native-messaging.md).

## Build the Windows agent

```powershell
cd services/windows-agent
./install/build-agent.ps1            # runs the tests, then publishes self-contained win-x64 binaries
# → artifacts/publish/{Service,NativeHost,Tray}
```

This also works from Linux or macOS with `pwsh` and the .NET 10 SDK (it cross-publishes). Sign the executables before distributing them; see [docs/windows-agent.md](docs/windows-agent.md).

## Enroll an endpoint

1. In the portal, open **Settings → Enrollment tokens** in the tenant (needs `tenant.settings.write`) and create a token. It is shown once.
2. On the endpoint, in an elevated PowerShell session:
   ```powershell
   .\install\install-agent.ps1 -ApiBaseUrl https://<your-app> -EnrollmentToken '<token>' `
       -ExtensionIds 'ikgimjohebonbmlfdngiiebaadojbdmp'
   .\install\verify-agent.ps1
   ```
3. On first start the service exchanges the token for a device credential and deletes the token file. Within a minute the device shows up under **Devices** with a heartbeat. The token decides the tenant; the endpoint cannot choose one.

## Create a blocked domain, publish, and verify blocking

1. Go to **Policies → Default Policy → Add rule** and add a **Block domain** rule for `phase1-block-test.example`. Subdomains are included.
2. Click **Publish**. The version number goes up, and older versions are kept unchanged.
3. Within one poll interval (5 minutes by default; the heartbeat triggers an immediate pull when a newer version exists), the agent verifies the checksum, caches the policy and pushes it to every connected browser. The device page shows the agent's policy version (_Current policy version_) and each browser's (_Applied policy_).
4. Browse to `https://phase1-block-test.example/`. You land on the extension's **"This site has been blocked"** page.

## Inspect a security event

Go to **Events**, filter by type `URL_BLOCKED`. Each event shows the time, device, browser, URL, domain, matched rule, policy version and threat category. The server validates and normalizes every event, and confirms the category against the policy version the device reported. Through the API: `GET /api/v1/organizations/<orgId>/events?eventType=URL_BLOCKED`.

## Run the tests

```bash
pnpm test                 # unit tests in every package (Vitest)
pnpm db:local && pnpm test:db      # tenant isolation (RLS) + API integration against real Postgres
pnpm build && pnpm test:e2e        # full stack: Next + Postgres + .NET agent + native host + Chromium
dotnet test services/windows-agent/BrowserSecurity.Agent.sln
pnpm lint && pnpm typecheck && pnpm format:check
```

CI (`.github/workflows/ci.yml`) runs all of them. Any failure blocks the build. If Playwright's pinned Chromium is not installed, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` to point the E2E test at an existing Chromium.

## End-to-end acceptance test

[docs/acceptance-test.md](docs/acceptance-test.md) walks through all 29 steps of the Phase 1 acceptance flow: clean Supabase, then a new tenant, enrollment, blocking in Chrome and Edge, the event, cross-tenant denial, and the audited platform tenant context. `tests/browser-e2e/full-stack.test.ts` automates the endpoint half on every CI run.

## Troubleshooting

| Symptom                                                      | Check                                                                                                                                                                                                                  |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Extension popup says **Degraded / agent unreachable**        | Is the service running (`Get-Service Vector58BrowserSecurity`)? Does `verify-agent.ps1` pass? Do the registry keys point at an existing manifest? Is the extension ID in both `allowed_origins` and `nativehost.json`? |
| `Specified native messaging host not found`                  | The registry key is missing, or the manifest path is wrong. Run `install-agent.ps1` again.                                                                                                                             |
| `Access to the specified native messaging host is forbidden` | The extension ID is not in `allowed_origins`. Store builds have different IDs from dev builds.                                                                                                                         |
| Device never appears                                         | Look in the Windows Event Log (Application, source `Vector58BrowserSecurity`). If the token was rejected it is deleted; create a new one. Check that `ApiBaseUrl` is https.                                            |
| Agent logs "device credential rejected"                      | The device was disabled or its tenant was disabled. The agent keeps enforcing its cached policy. Enable the device or re-enroll it.                                                                                    |
| Policy published but browsers keep the old version           | Check the device page. The agent rejects policies with checksum, tenant or rollback problems and reports `POLICY_FAILED` in **Events**.                                                                                |
| Platform admin sees "not found" in a tenant                  | They have not entered tenant context, or it expired after 60 minutes. Enter it from **Customers → tenant**.                                                                                                            |
| `/api/internal/*` returns 401                                | `CRON_SECRET` is unset, shorter than 32 characters, or does not match between caller and app.                                                                                                                          |

## Security considerations

- Tenant isolation is enforced in the database (RLS on every table, composite foreign keys) **and** in server authorization. Browser roles can only SELECT, and every write goes through server code that checks named permissions.
- No secrets in source control. A unit test scans the repository. Device secrets and enrollment tokens are stored only as SHA-256 hashes, and their columns are hidden from browser roles.
- Endpoints cannot choose their tenant, cannot set their public IP (the server reads it from trusted proxy headers), and cannot push policy to the agent.
- Published policy versions are immutable. The agent and the extension each verify the checksum, refuse rollbacks and policies for other tenants, and keep the last-known-good policy when anything fails, including cloud and agent outages.
- Platform access to tenant data is explicit, time-boxed and audited. Privileged actions are written to an append-only audit log.
- The agent runs only a fixed set of commands. It never downloads or runs remote code. Browsing history is never uploaded in Phase 1.

Threat model and design rationale: [docs/security-model.md](docs/security-model.md).

## Known Phase 1 limitations

- **Browser-history collection** is modeled end to end (incident-bound, time-boxed, permission-gated, audited), but the agent answers `NOT_SUPPORTED`. No history is ever read.
- The device credential is a bearer secret protected by DPAPI and TLS. Keypair or TPM-bound device identity comes in Phase 2; the `publicKey` field is already reserved.
- Policy integrity uses a SHA-256 checksum over canonical JSON, not a signature. The `signature` field is reserved and excluded from the checksum.
- History requests need both the request and approve permissions, but the same person can hold both. A true two-person rule comes in Phase 2.
- There is no API rate limiting yet. Rely on Vercel and WAF limits.
- The native host trusts any process the signed-in user runs that connects to the pipe with an allowed origin claim. It cannot push policy, but it could send fake telemetry. Verifying the client process image comes in Phase 2.
- Domain rules beyond the regex budget (about 900 rules) redirect without carrying the original URL. Blocking is unaffected; only the URL shown and reported is less specific.
- Policies over 1 MiB serialized (well above the 4,500-rule cap) cannot cross native messaging. The agent reports `POLICY_FAILED`.
- Windows only. No macOS or Linux agent, no Firefox or Safari, no billing.

## Phase 2 roadmap

- Device keypair and TPM attestation, mTLS, signed policies (detached signature)
- Browser-history collection with a two-person approval rule and evidence retention policies
- Signed MSI installer, auto-update channel from `agent_releases` and `extension_releases`, code signing in CI
- Per-group policies, policy scheduling and staged rollout
- More threat feeds (commercial providers behind `ThreatFeedProvider`), reputation scoring
- SSO (SAML/OIDC) and SCIM for tenant users
- API rate limiting, per-tenant quotas, billing and plan limits (columns are already on `organizations`)
- macOS agent, Firefox support
