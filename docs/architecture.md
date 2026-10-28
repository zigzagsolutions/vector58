# Architecture

## Components

| Component                       | Runs on                                          | Responsibility                                                                                                                                                    |
| ------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Admin portal** (`apps/admin`) | Vercel (Node.js runtime)                         | Platform console (`/platform/*`) and tenant console (`/o/<orgId>/*`), server actions, versioned REST API (`/api/v1`), scheduled job endpoints (`/api/internal/*`) |
| **Database**                    | Supabase Postgres                                | Source of truth. RLS on every table. Authorization functions shared by RLS and the server.                                                                        |
| **Auth**                        | Supabase Auth                                    | Admin identities (email and password, invite-only). Sessions in httpOnly cookies refreshed by `src/proxy.ts`.                                                     |
| **Edge Functions**              | Supabase                                         | Scheduled triggers that call `/api/internal/*` with `CRON_SECRET`                                                                                                 |
| **Windows service**             | Endpoint, LocalSystem                            | Enrollment, heartbeat, policy sync and verification, last-known-good cache, commands, event upload, browser bridge                                                |
| **Native messaging host**       | Endpoint, signed-in user, started by the browser | Relays framed JSON between the extension (stdio) and the service (named pipe)                                                                                     |
| **Tray**                        | Endpoint, signed-in user                         | Read-only status. "Check for updates". Cannot disable protection.                                                                                                 |
| **Extension**                   | Chrome and Edge (MV3)                            | Verifies and applies policy as `declarativeNetRequest` dynamic rules, shows the block page, reports events                                                        |

## Request paths

**Admin:** browser → Next.js server component, server action or API route → `Authorizer` (session → user → permissions through the SQL functions) → service function → `pg`.

- Reads that should follow the user's visibility run in `withUserTx`. That sets `role authenticated` and `request.jwt.claims`, so the same RLS policies that guard PostgREST apply. This is defense in depth on top of the authorizer.
- Writes run in `withServiceTx` only **after** the authorizer has checked a named permission for an explicit tenant. Every write sets `organization_id` from that checked context, never from the request body.

**Device:** agent → `POST /api/v1/device/*` with `Authorization: Device <deviceId>.<secret>`. The server hashes the secret, loads the device, and takes the tenant from the device row. A disabled device or tenant returns 401 or 403; the agent keeps enforcing its cache.

**Browser:** extension ⇄ native host (stdio, 4-byte little-endian length + UTF-8 JSON) ⇄ service (named pipe, same framing). The service is the only component that talks to the cloud.

## Policy flow

```
admin adds rule ─▶ policy_rules (soft-deletable, tenant-scoped)
admin publishes ─▶ compiler: global indicators (≥ confidence, active, not expired)
                             + tenant rules (enabled, not expired)
                             − platform safe list for globals
                             → precedence bands, deterministic rule ids, sorted
                             → checksum = sha256(canonicalJson(payload))
                ─▶ policy_versions (immutable; previous → superseded)
agent heartbeat ─▶ latestPolicyVersion > cached? → GET /device/policy
agent           ─▶ validate schema → verify checksum → same tenant? → no rollback
                ─▶ cache to disk (current.json, previous.json) → push to browsers
extension       ─▶ validate → verify checksum → same tenant? → no rollback
                ─▶ convert to DNR → diff → atomic updateDynamicRules → POLICY_STATUS
```

Details: [policy-engine.md](policy-engine.md).

## Event flow

blocked navigation → DNR redirect to `blocked.html?r=<ruleId>#<url>` → the page asks the service worker to report → the worker re-checks the rule and URL against the applied policy → `SECURITY_EVENT` to the host → the service validates the type, id and size and adds it to a durable queue → `POST /api/v1/events/security` in batches of up to 500 → the server normalizes the URL and domain, takes the category from the stored policy version, and de-duplicates on `(device_id, source_event_id)`.

## Failure behavior

| Failure                                           | Behavior                                                                                                                     |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Cloud unreachable                                 | Agent keeps its last-known-good policy, queues events (10,000 max), backs off up to 10 minutes. Browsers are unaffected.     |
| Policy fails validation (agent)                   | Rejected, previous kept, `POLICY_FAILED` reported (`stage: agent`)                                                           |
| Policy fails validation or DNR update (extension) | `updateDynamicRules` is atomic, so old rules stay. `POLICY_STATUS failed` and `POLICY_FAILED` are reported.                  |
| Agent or native host down                         | Extension keeps its DNR rules, shows a degraded badge, queues events (500 max), reconnects with backoff and a 1-minute alarm |
| Agent restart while offline                       | Loads and re-verifies the cached policy before any network call, then serves it to browsers                                  |
| Cached policy tampered or corrupt                 | Falls back to `previous.json`, or to nothing, rather than an unverified policy                                               |

## Data model (main tables)

`organizations` · `profiles` · `roles` / `permissions` / `role_permissions` · `organization_users` / `organization_user_roles` · `platform_user_roles` · `platform_tenant_contexts` · `enrollment_tokens` · `devices` · `browser_clients` · `policies` / `policy_rules` / `policy_versions` · `threat_sources` / `threat_indicators` / `threat_observations` · `allowlist_entries` · `security_events` · `incidents` / `endpoint_commands` / `incident_artifacts` · `audit_events`.

Every tenant-owned table has `organization_id`. Child tables reference parents through composite `(id, organization_id)` foreign keys, so the database rejects cross-tenant references even from privileged code.

## Multi-tenancy readiness

Vector58's own company is a normal tenant. `organizations` already carries plan, status and limits columns for future billing. Platform staff reach tenants only through audited tenant contexts. Adding a customer means creating an organization, assigning an owner and issuing enrollment tokens. No code changes.
