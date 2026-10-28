# Security model

## Assets and trust boundaries

| Asset                                                        | Protected by                                                                                                                                       |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant data (devices, policies, events, incidents, evidence) | RLS on every table, server authorization, composite foreign keys                                                                                   |
| Policy integrity                                             | Immutable versions, canonical-JSON SHA-256 checksum verified by the agent and the extension, rollback refusal, tenant binding                      |
| Device credential                                            | 32 random bytes, returned once, stored as SHA-256 on the server and with DPAPI on the endpoint, presented only to the control plane that issued it |
| Enrollment tokens                                            | Stored as SHA-256, max uses and expiry, revocable. The installer drops them in a SYSTEM-only directory and they are deleted after use.             |
| Audit trail                                                  | Append-only table (update, delete and truncate blocked by triggers)                                                                                |

Trust boundaries: browser ⇄ portal (session cookie, CSRF origin check), endpoint ⇄ API (device credential, TLS), extension ⇄ native host ⇄ service (allow-listed origin, pipe ACL, message-type allow-lists), platform ⇄ tenant (explicit, audited tenant context).

## Authorization

- **Single source of truth.** `packages/auth-permissions` defines permissions and roles. Migration `…09` is generated from it and a test fails if they drift. The SQL functions `permitted_organization_ids(permission)` and `has_tenant_permission(org, permission)` evaluate memberships, roles and active tenant contexts. RLS policies and the server `Authorizer` both call them, so the UI, the API and the database cannot disagree.
- **No `isAdmin`.** Checks name a permission. An ESLint rule rejects `isAdmin`.
- **No privilege escalation.** A user can assign only roles whose permissions are a subset of their own. The last owner cannot be removed or demoted.
- **Not-found, not forbidden.** Accessing another tenant's resource returns 404, so tenant and resource ids cannot be probed. Missing permissions _within_ your own tenant return 403.

### Role matrix (tenant permissions)

| Permission                                        |   Owner   | Security Admin |    Analyst    | Help Desk |
| ------------------------------------------------- | :-------: | :------------: | :-----------: | :-------: |
| users.read / write                                |   ✓ / ✓   |     ✓ / ✓      |     – / –     |   ✓ / –   |
| devices.read / manage                             |   ✓ / ✓   |     ✓ / ✓      |     ✓ / –     |   ✓ / –   |
| policy.read / write / publish                     | ✓ / ✓ / ✓ |   ✓ / ✓ / ✓    |   ✓ / – / –   | ✓ / – / – |
| events.read                                       |     ✓     |       ✓        |       ✓       |     ✓     |
| incident.read / create                            |   ✓ / ✓   |     ✓ / ✓      |     ✓ / ✓     |   – / –   |
| incident.history.request                          |     ✓     |       ✓        |       ✓       |     –     |
| incident.history.approve / read / export / delete |     ✓     |       –        |       –       |     –     |
| audit.read, settings.read                         |     ✓     |       ✓        | settings only |     –     |
| settings.write                                    |     ✓     |       –        |       –       |     –     |

### Platform roles

| Role           | Platform permissions                                                                        | Inside an entered tenant                                              |
| -------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Super Admin    | all                                                                                         | everything except browser-history evidence                            |
| Security Admin | tenants/users read, threats manage, policy manage, incidents read, audit read, enter tenant | read-only, plus devices.manage, policy.write/publish, incident.create |
| Support        | tenants/users read, enter tenant                                                            | users/devices/policy/events/settings read                             |
| Auditor        | tenants read, audit read, incidents read                                                    | cannot enter tenants                                                  |

## Platform tenant context

Platform users are never tenant members. To act inside a tenant they _enter tenant context_, which requires `platform.support.enter_tenant` and a reason:

- One active context per user, expiring after 60 minutes. It is enforced by a unique index and checked by the SQL functions, so an expired context grants nothing at the RLS level either.
- It grants only the role's `tenantContextPermissions`.
- Entry and exit are written to the audit log (`PLATFORM_ADMIN_ENTERED_TENANT` / `…EXITED_TENANT`), visible to both the platform and the tenant. Every action taken inside records the `tenant_context_id`.
- The UI shows a persistent "Viewing Tenant" banner. There is no impersonation: actions are attributed to the platform user.

## Endpoint security

- The tenant comes from the enrollment token at enrollment and from the device record afterwards. A request body cannot change it.
- Public IP is recorded server-side according to `TRUSTED_PROXY_MODE`. Client-reported `localIp` is informational only.
- The device secret is protected with DPAPI (CurrentUser scope under LocalSystem, plus entropy) in `%ProgramData%\Vector58\BrowserSecurity`, which has an ACL limited to SYSTEM and Administrators with inheritance disabled. The identity is bound to the configured `ApiBaseUrl`: if the URL changes, the secret is not sent.
- The agent accepts http only for loopback, and only with an explicit development flag.
- Commands are a fixed enum (`REFRESH_POLICY`, `COLLECT_DIAGNOSTICS`, `CHECK_EXTENSION_STATUS`, `COLLECT_BROWSER_HISTORY`). Unknown commands fail. There is no way to deliver or run code remotely.
- **Named pipe.** Interactive users may read and write but not create instances, which prevents squatting. Network logons are denied, and the first instance is created with `FirstPipeInstance`. The service accepts only extension-to-host message types, validates events (type allow-list, UUID id, 16 KiB cap), and **never accepts policy from a pipe client**.
- **Native host.** It checks the caller origin against its allow-list (the browser's `allowed_origins` is the first gate) and relays only allow-listed message types in each direction, with size limits (1 MiB to the browser, 4 MiB from it).

## Browser enforcement integrity

- The extension re-verifies the checksum, schema, tenant and version monotonicity itself. A compromised or buggy host cannot downgrade or swap the policy.
- `updateDynamicRules` is atomic, so a failed update leaves the previous rules in force.
- The block page is web-accessible (redirect targets must be). Reports from it are therefore re-validated: the sender must be this extension's own `blocked.html`, the rule must be a block rule in the applied policy, and the URL must match that rule. Forged reports are dropped.
- Enterprise force-install (see [browser-extension.md](browser-extension.md)) stops users from disabling or removing the extension.

## Web application

- Security headers are set in `next.config.ts`: a CSP with `frame-ancestors 'none'`, `form-action 'self'` and `object-src 'none'`, plus `X-Frame-Options`, HSTS, `nosniff`, a strict referrer policy and a permissions policy. A nonce-based script CSP is on the Phase 2 list.
- Cookie-authenticated mutations require a same-origin `Origin` header (`assertSameOrigin`). The API rejects non-JSON bodies.
- Every input is validated with Zod at the boundary, and URLs and domains are normalized server-side.
- Errors use a versioned envelope. Internal errors never leak details.

## Secrets

Nothing secret is in the repository: `tests/unit/no-secrets.test.ts` scans for key patterns. Server-only variables have no `NEXT_PUBLIC_` prefix and are read through a lazily validated `serverEnv()`. Server modules import `server-only`, and lint forbids importing `@/server/db` outside `src/server`. The Supabase secret key is used only for invitations.

## Audit

Privileged actions (tenant lifecycle, membership and roles, tenant context, rules, publishing, tokens, devices, commands, incidents, evidence access, threat intel) write `audit_events` with the actor, an email snapshot, the tenant, the context id, the target, metadata, IP and user agent. The table is append-only at the database level.
