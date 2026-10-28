# Tenant isolation

Tenant isolation is the top priority. It is enforced in three independent layers, and each layer is tested against a real Postgres database, not at the UI level.

## 1. Database: row-level security

- **RLS is enabled on every table in `public`**, and a test fails if a new table is added without it.
- Browser-facing roles (`anon`, `authenticated`) have **no write privilege on any table**. `authenticated` gets `SELECT` only, filtered by policies like:
  ```sql
  create policy devices_select on public.devices for select to authenticated
    using (organization_id in (select public.permitted_organization_ids('tenant.devices.read')));
  ```
- `permitted_organization_ids(permission)` returns the organizations where the caller has that permission through an active membership in an active tenant, **or** through an unexpired platform tenant context whose role grants it. It is `security definer` with an empty `search_path` and reads `auth.uid()` from the JWT.
- Column-level grants hide secrets: `devices.credential_hash` and `enrollment_tokens.token_hash` cannot be selected by `authenticated`.
- Every tenant-owned child row references its parent through a composite `(id, organization_id)` foreign key, so even the service connection cannot link an event to another tenant's device.
- `anon` can read nothing.

## 2. Server: explicit tenant scoping

- The server never trusts a tenant id from the client. `/api/v1/organizations/<id>/…` and `/o/<orgId>/…` take the id from the path only to _ask_ the `Authorizer` whether the caller holds the required permission there. The answer comes from the same SQL functions as RLS.
- Service functions receive a `TenantActor` (organization id, user, permissions, optional tenant context) and include `organization_id = $actor.organizationId` in every query. A resource id from another tenant returns **404**.
- User-visibility reads run with the user's JWT claims under `role authenticated`, so RLS applies to server code too.
- Device APIs take the tenant from the authenticated device row. Event bodies cannot name a tenant or device.

## 3. Endpoint: tenant binding

- Enrollment derives the tenant from the token. The agent cannot choose one.
- The agent and the extension each refuse a policy whose `organizationId` differs from the device's (or the currently applied) tenant.

## Platform staff

Platform users have no tenant membership. Without an entered context, a Platform Super Admin sees the tenant list (`platform.tenants.read`) and **no tenant operational data**. An entered context:

- is limited to one tenant, one at a time, for 60 minutes;
- grants only the platform role's `tenantContextPermissions`. Support is read-only, and nobody gets browser-history evidence;
- is audited on entry and exit, and is visible in the tenant's own audit log.

## Test coverage (`tests/tenant-isolation/rls.test.ts`, `tests/integration/api-flow.test.ts`)

| Area               | What is proven                                                                                                                                                          |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema guarantees  | RLS on every table; `organization_id` on every tenant-owned table; no browser-role write privileges                                                                     |
| Cross-tenant reads | For each tenant role, every tenant table of the other tenant is invisible, with **positive controls** proving their own data is visible                                 |
| Id guessing        | Targeting another tenant's device or policy id directly returns nothing (RLS) or 404 (API)                                                                              |
| Writes             | Tenant users cannot write directly even in their own tenant; every mutation goes through the API                                                                        |
| Secrets            | Device credential hashes are unreadable by browser sessions                                                                                                             |
| Helpers            | `permitted_organization_ids` and related functions do not reveal other tenants                                                                                          |
| Granularity        | Help desk cannot see incidents or audit; analyst cannot see audit or the user directory; evidence needs `tenant.incident.history.read`                                  |
| Anonymous          | `anon` reads nothing                                                                                                                                                    |
| Platform context   | No data without context; context grants exactly one tenant per role; expired contexts grant nothing; the auditor reads audit only; tenant users never see platform data |
| Lifecycle          | Disabled tenants and removed members lose access immediately                                                                                                            |
| Integrity          | Audit log append-only; policy versions immutable; composite foreign keys reject cross-tenant links; role scope triggers                                                 |
| API flow           | Platform and tenant authorization, privilege-escalation guard, tenant context, enrollment, publish, events, commands, audit, all across two tenants                     |
| End to end         | The browser E2E confirms another tenant cannot see the `URL_BLOCKED` event                                                                                              |

Run them with `pnpm db:local && pnpm test:db`.
