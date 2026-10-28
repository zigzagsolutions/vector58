# Incident response

Phase 1 provides the incident and endpoint-command foundation. Browsing history is **not** collected. The command exists end to end and the agent answers `NOT_SUPPORTED`.

## Incidents

**Incidents → New** (needs `tenant.incident.create`) records a title, description and severity (`low` to `critical`). Incidents are tenant-scoped like everything else, and creation is audited (`INCIDENT_CREATED`). The incident page shows its commands, their status and their artifacts.

## Endpoint commands

| Command                   | What the agent does                                                                                                      | Result                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `REFRESH_POLICY`          | Policy sync now                                                                                                          | outcome and agent policy version (`FAILED` if rejected or unreachable) |
| `CHECK_EXTENSION_STATUS`  | Lists known browsers; asks each connected extension for diagnostics (5 s timeout)                                        | browsers, extension reports                                            |
| `COLLECT_DIAGNOSTICS`     | Gathers agent version, OS, uptime, cloud health, policy version and checksum, queue size, browsers and extension reports | operational data only: no URLs, files or credentials                   |
| `COLLECT_BROWSER_HISTORY` | **Not supported in Phase 1**                                                                                             | `FAILED` with `NOT_SUPPORTED: …` and the incident id                   |

Lifecycle: `PENDING` (issued) → `RECEIVED` (agent polled; `FOR UPDATE SKIP LOCKED`) → `RUNNING` (optional) → `COMPLETED` or `FAILED`. Commands not picked up before `expires_at` become `EXPIRED`, either through maintenance or when the device polls. The server enforces the transitions. Results tied to an incident are stored as `incident_artifacts` (`diagnostics`, `extension_status`, `browser_history`).

Permissions: commands tied to an incident need `tenant.incident.create`; standalone device commands need `tenant.devices.manage`. Every issued command is audited (`ENDPOINT_COMMAND_ISSUED`). The command set is a fixed enum. There is no way to send scripts or binaries to endpoints.

## Browser-history collection (designed, not enabled)

The permissions are deliberately split:

| Permission                        | Owner | Security Admin | Analyst | Platform (any) |
| --------------------------------- | :---: | :------------: | :-----: | :------------: |
| `tenant.incident.history.request` |   ✓   |       ✓        |    ✓    |       –        |
| `tenant.incident.history.approve` |   ✓   |       –        |    –    |       –        |
| `tenant.incident.history.read`    |   ✓   |       –        |    –    |       –        |
| `tenant.incident.history.export`  |   ✓   |       –        |    –    |       –        |
| `tenant.incident.history.delete`  |   ✓   |       –        |    –    |       –        |

Rules already enforced:

- Issuing `COLLECT_BROWSER_HISTORY` requires **both** request and approve, an **incident**, and a window of at most **7 days** (`CollectBrowserHistoryPayloadSchema`). `approvedBy` is recorded and the action is audited (`HISTORY_COLLECTION_REQUESTED`).
- `browser_history` artifacts are hidden by RLS unless the reader holds `tenant.incident.history.read`. Viewing and exporting are audited (`INCIDENT_EVIDENCE_VIEWED` / `INCIDENT_EVIDENCE_EXPORTED`).
- No platform role, Super Admin included, has any history-evidence permission inside a tenant context.
- There is no continuous upload. The extension has no `history` permission. The native message `COLLECT_HISTORY` is answered with `unsupported`.

Phase 2 adds a true two-person rule (requester ≠ approver, a separate approval record), extension-side bounded collection behind an explicit permission prompt, encryption of artifacts at rest, and retention and deletion policies.

## Investigating a block

1. **Events**: filter by device, domain, type or date. Each `URL_BLOCKED` shows the rule and policy version that blocked it.
2. **Devices → device**: protection status, agent and browser policy versions, recent commands.
3. Create an incident. Issue `CHECK_EXTENSION_STATUS` or `COLLECT_DIAGNOSTICS` to capture endpoint state as an artifact.
4. If it was a false positive, add an **Allow** rule for the domain (it outranks global blocks) and publish.
