# Native messaging

The extension never talks to the cloud. It talks to the local agent through Chromium native messaging:

```
extension ──connectNative("com.vector58.browser_security")──▶ BrowserSecurity.NativeHost.exe (per browser profile, user context)
                                                                  │ named pipe \\.\pipe\Vector58.BrowserSecurity.Browser
                                                                  ▼
                                                          BrowserSecurity.Agent.Service (LocalSystem)
```

## Framing

Each message is a 32-bit **little-endian** length followed by UTF-8 JSON. Chromium limits host→extension messages to **1 MiB**. The host enforces 1 MiB toward the browser and 4 MiB from it, and the pipe uses the same framing so frames are relayed unchanged.

## Host manifest

Written by `install-agent.ps1` next to the host executable:

```json
{
  "name": "com.vector58.browser_security",
  "description": "Vector58 Browser Security agent bridge",
  "path": "C:\\Program Files\\Vector58\\BrowserSecurity\\NativeHost\\BrowserSecurity.NativeHost.exe",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<chrome-id>/", "chrome-extension://<edge-id>/"]
}
```

It is registered (the default value is the manifest path) under:

- `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vector58.browser_security`
- `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.vector58.browser_security`

On Linux and macOS (development and E2E only) the manifest goes in the browser profile's `NativeMessagingHosts/` directory. `tests/browser-e2e/stack.ts` shows how.

## Connection lifecycle

1. The extension's service worker calls `connectNative` on start, on install, on startup and from a 1-minute keepalive alarm. An open port keeps the MV3 worker alive.
2. The browser starts the host with the caller origin as its first argument. The host checks it against `nativehost.json` (`allowedExtensionIds`). The browser's own `allowed_origins` check has already happened.
3. The host connects to the service pipe (3 s timeout) and sends `HOST_HELLO {origin, hostVersion, hostPid}`. The service checks the origin against its own `AllowedExtensionIds`.
4. The extension sends `CLIENT_HEALTH`, `REQUEST_POLICY`, then flushes queued events.
5. If the agent is unreachable, the host exits. The extension marks itself **degraded** (badge `!`, popup message), **keeps its DNR rules**, queues events, and reconnects with exponential backoff (1 s up to 60 s, with jitter).

## Messages

All messages carry `type` and optionally `id` and `protocolVersion` (currently `1`). Schemas: `packages/policy-types/src/native-messaging.ts`.

| Type                 | Direction         | Purpose                                                                                                |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------------------ |
| `POLICY_UPDATE`      | agent → extension | `{policyVersion, payload}`. The full compiled payload, verified again by the extension.                |
| `POLICY_STATUS`      | extension → agent | `applied` / `unchanged` / `failed`, with rule count and error                                          |
| `REQUEST_POLICY`     | extension → agent | `{currentVersion}`. The agent always answers with its cached policy (cheap `unchanged`, self-healing). |
| `CLIENT_HEALTH`      | extension → agent | browser, versions, policy version, DNR rule count. Reported in heartbeats.                             |
| `SECURITY_EVENT`     | extension → agent | `URL_BLOCKED`, `POLICY_APPLIED`, `POLICY_FAILED`, `EXTENSION_CONNECTED`, `EXTENSION_DISCONNECTED`      |
| `COLLECT_HISTORY`    | both              | Phase 1: the extension answers `result.status = "unsupported"`                                         |
| `DIAGNOSTIC_REQUEST` | both              | The agent asks; the extension answers with `response` (versions, rule count, queue length, last error) |
| `HOST_HELLO`         | host → agent      | First frame on the pipe; never sent by the browser                                                     |

## Allow-lists and limits

| Hop                          | Accepted                                                                                                      |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------- |
| extension → host → agent     | `POLICY_STATUS`, `REQUEST_POLICY`, `CLIENT_HEALTH`, `SECURITY_EVENT`, `COLLECT_HISTORY`, `DIAGNOSTIC_REQUEST` |
| agent → host → extension     | `POLICY_UPDATE`, `COLLECT_HISTORY`, `DIAGNOSTIC_REQUEST`                                                      |
| events accepted by the agent | extension event types only, UUID `eventId`, ≤ 16 KiB                                                          |

Anything else is dropped and logged to stderr. In particular, **a pipe client can never push policy to the agent**, and the extension ignores message types it does not know.

## Pipe security (Windows)

The ACL lets Authenticated Users read and write but not create pipe instances, which prevents name squatting. SYSTEM and Administrators get full control and network logons are denied. The service creates the first instance with `FirstPipeInstance`. Phase 2 will also verify the connecting process image (`GetNamedPipeClientProcessId`) against the signed host binary.

## Tests

- `FramingTests`: byte layout, size limits, truncation
- `NativeHostRelayTests`: strict origin parsing, refusal of unknown extensions, the agent being down, and a full relay between an in-memory browser, the real host relay, a real named pipe and the real bridge
- `NativeHostShutdownTests`: the host exits when the agent goes away even while a stdin read is pending
- `BrowserBridgeTests`: policy on request and broadcast, forged events, a forged `POLICY_UPDATE` from a pipe client, origin rejection, diagnostics
- `tests/browser-e2e`: Chromium → .NET host → .NET service over the real protocol
