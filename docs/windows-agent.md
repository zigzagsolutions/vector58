# Windows agent

`services/windows-agent/BrowserSecurity.Agent.sln` (.NET 10):

| Project                                 | Output                              | Runs as                                                                                     |
| --------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------- |
| `BrowserSecurity.Agent.Shared`          | library                             | canonical JSON, policy validation and checksum, framing, API and IPC models, tray presenter |
| `BrowserSecurity.Agent.Service`         | `BrowserSecurity.Agent.Service.exe` | Windows Service `Vector58BrowserSecurity`, LocalSystem, automatic start                     |
| `BrowserSecurity.Agent.NativeMessaging` | `BrowserSecurity.NativeHost.exe`    | started by Chrome or Edge in the user session                                               |
| `BrowserSecurity.Agent.Tray`            | `BrowserSecurity.Tray.exe`          | per user at sign-in (WinForms notification-area icon)                                       |
| `BrowserSecurity.Agent.Tests`           | xUnit                               | any OS (named pipes work on Linux for tests)                                                |

## Service internals

Interfaces, all registered in `AgentServices.Add`: `IApiClient`, `IDeviceIdentityProvider`, `ISecretProtector`, `IPolicyStore`, `IPolicySyncService`, `IBrowserBridge`, `IHeartbeatService`, `ICommandService`, `ISecurityEventQueue`, `ISystemInfo`.

`AgentRuntime` startup order:

1. Load and **re-verify** the cached policy (`policy/current.json`, falling back to `previous.json`).
2. Start the browser pipe and status pipe. Browsers get the cached policy right away, even offline.
3. Queue `AGENT_STARTED`.
4. Enroll if needed: read `enrollment.token`, `POST /api/v1/device/enroll`, store the identity and the DPAPI secret, delete the token. A rejected token is deleted; network errors retry with backoff.
5. Run loops: heartbeat (60 s), policy (300 s, or sooner when a heartbeat reports a newer version), commands (60 s, or sooner when commands are pending), event upload (15 s, batches of 500). Failures back off up to 10 minutes. A 401 or 403 is logged and the agent keeps enforcing.

Data directory `%ProgramData%\Vector58\BrowserSecurity` (ACL: SYSTEM and Administrators only):

| File                                   | Contents                                                                          |
| -------------------------------------- | --------------------------------------------------------------------------------- |
| `agentsettings.json`                   | `Agent:ApiBaseUrl`, `PortalUrl`, `AllowedExtensionIds` (written by the installer) |
| `enrollment.token`                     | one-time token, deleted after enrollment                                          |
| `installation.id`                      | stable per-install UUID (re-enrolling updates the same device record)             |
| `identity.json`                        | device id, tenant id and name, enrolled-at, API base URL                          |
| `device.secret`                        | device secret, DPAPI-protected                                                    |
| `policy/current.json`, `previous.json` | raw verified payloads                                                             |
| `events/queue.jsonl`                   | durable event queue (10,000 max)                                                  |

## Configuration

Precedence: `appsettings.json` (next to the exe), then `agentsettings.json` (data directory), then environment variables `BSP_Agent__<Name>`.

| Setting                                                                                                               | Default            | Notes                                                        |
| --------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------------------------------------------------ |
| `ApiBaseUrl`                                                                                                          | –                  | https required                                               |
| `PortalUrl`                                                                                                           | –                  | shown in the tray                                            |
| `AllowedExtensionIds`                                                                                                 | dev ID             | Chrome Web Store and Edge Add-ons IDs for production         |
| `HeartbeatIntervalSeconds` / `PolicyPollIntervalSeconds` / `CommandPollIntervalSeconds` / `EventFlushIntervalSeconds` | 60 / 300 / 60 / 15 |                                                              |
| `AllowInsecureLocalhost`                                                                                              | false              | development only: http to loopback                           |
| `AllowUnprotectedSecretStorage`                                                                                       | false              | development only, non-Windows: no DPAPI. Ignored on Windows. |

## Build

```powershell
cd services/windows-agent
./install/build-agent.ps1                 # tests, then self-contained win-x64 single-file publish → artifacts/publish
```

`dotnet build` and `dotnet test` also run on Linux and macOS. The tray builds there through `EnableWindowsTargeting` but runs only on Windows.

**Signing (required for production):** sign `BrowserSecurity.Agent.Service.exe`, `BrowserSecurity.NativeHost.exe` and `BrowserSecurity.Tray.exe` with your code-signing certificate (`signtool sign /fd SHA256 /tr <tsa> /td SHA256`) before distribution. `build-agent.ps1` marks where.

## Install on a clean endpoint

Run these from an elevated PowerShell 7 session, from a copy of `services/windows-agent` that contains `artifacts/publish`:

| Step                                                                                                                  | Command / result                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Build service, tray and native host                                                                                   | `./install/build-agent.ps1` (or copy the CI artifact `windows-agent`)                                                                     |
| Install, configure native messaging, register Chrome and Edge hosts, install and start the service, register the tray | `./install/install-agent.ps1 -ApiBaseUrl https://<app> -EnrollmentToken <token> -ExtensionIds <chrome-id>,<edge-id>`                      |
| Launch the tray now                                                                                                   | `& "$env:ProgramFiles\Vector58\BrowserSecurity\Tray\BrowserSecurity.Tray.exe"` (it starts automatically at the next sign-in)              |
| Verify install, enrollment, heartbeat and policy version                                                              | `./install/verify-agent.ps1`: checks the service, registry keys, manifest, enrollment and cached policy, then prints the live status JSON |
| Force-install the extension (optional, no GPO)                                                                        | `./install/configure-browser-policies.ps1 -ChromeExtensionId <id> -EdgeExtensionId <id>`                                                  |
| Uninstall                                                                                                             | `./install/uninstall-agent.ps1 [-KeepData]`                                                                                               |

No manual registry edits are needed. In the portal, the device appears under **Devices** with its heartbeat. After the first publish, _Current policy version_ shows the agent's version and the browser table shows each browser's.

## Status and logs

- `BrowserSecurity.Agent.Service.exe status` prints the live snapshot from the status pipe.
- Event Viewer → Windows Logs → Application, source `Vector58BrowserSecurity`.
- Tray: green shield means protected; a warning icon means degraded (cloud unreachable for more than 10 minutes, no connected browser, or a browser behind the agent's policy); an error icon means the service is down or the device is not enrolled. _Close status icon_ only closes the tray.

## Verified vs. unverified in this repository

Verified automatically: everything in `BrowserSecurity.Agent.Tests` (87 tests, run on Linux and on `windows-latest` in CI), the service and native host running end to end on Linux against the real API and Chromium, a win-x64 cross-publish, and PowerShell parse checks of every script.

Needs a Windows endpoint to verify: the service control manager integration, DPAPI at runtime, the pipe ACLs, the Event Log source, the tray UI, the registry-based host registration in Chrome and Edge, and the install scripts' runtime behavior. Follow [acceptance-test.md](acceptance-test.md).
