# Browser extension (Chrome and Edge)

One Manifest V3 codebase in `apps/extension`, built per browser into `dist/chrome` and `dist/edge`. The builds differ only in name and the `__BROWSER__` constant, which is reported in events.

## Build

```bash
pnpm --filter @bsp/extension build                 # development: includes the dev public key
pnpm --filter @bsp/extension build -- --release    # store: no "key", minified, no source maps
BSP_EXTENSION_VERSION=1.2.3 pnpm --filter @bsp/extension build -- --release
```

## Load for development

**Chrome**

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select `apps/extension/dist/chrome`.
4. Check that the ID is `ikgimjohebonbmlfdngiiebaadojbdmp`.

**Edge**

1. Open `edge://extensions`.
2. Turn on **Developer mode** (left pane).
3. Click **Load unpacked** and select `apps/extension/dist/edge`.
4. Check that the ID is `ikgimjohebonbmlfdngiiebaadojbdmp`.

Native messaging needs the agent installed (see [windows-agent.md](windows-agent.md)) with this ID in `-ExtensionIds`. Without the agent the popup shows _Waiting for first policy_ or _Degraded_.

## Extension IDs

| Build                  | ID                                            | Where it comes from                                                                                                            |
| ---------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Development (unpacked) | `ikgimjohebonbmlfdngiiebaadojbdmp`            | `manifest.key` = `static/dev-public-key.txt`. The matching private key was discarded; it is never needed for unpacked loading. |
| Chrome Web Store       | assigned by Google on first upload            | Upload the `--release` build. Note the ID.                                                                                     |
| Edge Add-ons           | assigned by Microsoft (differs from Chrome's) | Upload the `--release` build of `dist/edge`. Note the ID.                                                                      |
| Self-hosted CRX        | derived from your signing key                 | Pack with your own private key (kept in a secret store, never in the repository)                                               |

Every production ID must go in **both** the native host's `allowed_origins` and the agent's `AllowedExtensionIds`. Pass them to `install-agent.ps1 -ExtensionIds <chrome-id>,<edge-id>`.

## Permissions

| Permission                     | Why                                                                        |
| ------------------------------ | -------------------------------------------------------------------------- |
| `declarativeNetRequest`        | Enforce policy as dynamic rules. Browsing is never observed in JavaScript. |
| `nativeMessaging`              | Talk to the local agent                                                    |
| `storage`                      | Last-applied policy metadata, client id, bounded event queue               |
| `alarms`                       | 1-minute keepalive and reconnect backstop                                  |
| `host_permissions: <all_urls>` | Required for DNR **redirect** rules (block page)                           |

There are no content scripts and no `tabs`, `history` or `webRequest` permissions. The extension page CSP is `script-src 'self'; object-src 'none'; base-uri 'none'`.

## How it enforces

1. `POLICY_UPDATE` arrives from the agent.
2. `applyPolicyUpdate` validates the schema, checks the envelope and payload versions match, **re-verifies the checksum**, checks the tenant matches the applied one, refuses rollbacks, and short-circuits if the policy is unchanged.
3. `convertPolicyRules` produces DNR rules (see [policy-engine.md](policy-engine.md)). Regexes are pre-checked with `isRegexSupported`.
4. `diffRules` computes the minimal remove and add sets. `updateDynamicRules` applies them **atomically**. On any error the previous rules stay.
5. The applier reports `POLICY_STATUS` and the `POLICY_APPLIED` or `POLICY_FAILED` event.

Dynamic rules persist across browser restarts. Enforcement does not depend on the service worker or the agent being alive.

## Block page and events

A blocked main-frame navigation redirects to `blocked.html?r=<ruleId>#<original-url>`. The page strips the fragment from history and asks the service worker to report it. The worker checks that the sender is its own `blocked.html`, that the rule is a block rule in the applied policy and that the URL matches it. Only then does it emit `URL_BLOCKED` (de-duplicated for 10 s) and return the verified domain and category for display. Reports that cannot be verified are dropped.

## Popup

Shows protection state, agent connection, policy version, active rules, last applied, queued events and version. It has no off switch.

## Enterprise deployment

Force-installing stops users from disabling or removing the extension.

**Chrome Enterprise / Group Policy:** set _ExtensionInstallForcelist_ (`HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`) to `<chrome-id>;https://clients2.google.com/service/update2/crx`. Optionally use _ExtensionSettings_ to pin it and block developer mode (`DeveloperToolsAvailability`, `ExtensionDeveloperModeSettings`).

**Microsoft Edge:** `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist` = `<edge-id>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`.

**Microsoft Intune:** use a Settings Catalog profile with _Google Chrome → Extensions → Configure the list of force-installed apps and extensions_ and _Microsoft Edge → Extensions → Control which extensions are installed silently_, with the same values. Deploy the agent as a Win32 app that wraps `install-agent.ps1`, passing the enrollment token from an Intune-managed secret.

**Without GPO or Intune:** `services/windows-agent/install/configure-browser-policies.ps1 -ChromeExtensionId … -EdgeExtensionId …` writes the same registry values.

Self-hosted `.crx` files require domain-joined or MDM-managed machines in Chrome. Pass your update manifest URL with `-ChromeUpdateUrl`.

## Tests

`apps/extension/test`: DNR conversion (ids, priorities, subdomains, lookalikes, regex budget and fallback, escaping, exact URLs, allow precedence), minimal diffs, the applier (valid, unchanged, malformed, tampered checksum, rollback, foreign tenant, version mismatch, removals, browser failure keeping old rules, regex fallback, empty policy), and the controller (handshake, protocol schema conformance, degraded and reconnect with queue flush, backoff, `COLLECT_HISTORY` unsupported, diagnostics, unknown messages, block-report validation and forgery, de-duplication, concurrent queueing). A Chromium DNR evaluator in `test/fakes.ts` asserts actual enforcement outcomes. The real-browser path is covered by `tests/browser-e2e`.
