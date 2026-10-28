# Policy engine

`packages/policy-engine` turns tenant rules and global threat intelligence into a **compiled policy payload**. The admin API runs it on publish. The extension and the C# agent re-verify its checksum.

## Inputs

- **Tenant rules** (`policy_rules`): `BLOCK_DOMAIN`, `BLOCK_URL`, `ALLOW_DOMAIN`, `ALLOW_URL`, each with a priority (0–999), a category, an optional expiry and an enabled flag. Values are normalized on input by `@bsp/url-normalizer`: lowercase, IDNA, trailing dot removed, `*.` prefix stripped (domain rules always include subdomains), default ports and fragments dropped for URLs.
- **Global indicators** (`threat_indicators`): active, not expired, and with `confidence ≥ minGlobalConfidence` (default 75). The policy can opt out with `include_global_threats = false`.
- **Platform safe list** (`allowlist_entries` with null organization): global indicators matching it are never emitted. A tenant's _own_ block rules are not filtered by it.

## Precedence

Rules are placed in priority bands, and the rule's own priority orders them inside the band without ever crossing into another band:

| Band                | Base | Meaning                                          |
| ------------------- | ---- | ------------------------------------------------ |
| `CRITICAL_PLATFORM` | 4000 | Reserved for platform emergency blocks (Phase 2) |
| `ORG_ALLOW`         | 3000 | Tenant allow exceptions                          |
| `ORG_BLOCK`         | 2000 | Tenant blocks                                    |
| `GLOBAL_BLOCK`      | 1000 | Global threat intelligence (+ confidence)        |

So a tenant allow beats a tenant block, which beats a global block. At equal DNR priority Chromium prefers `allow`, and the compiler's `decide()` reproduces that tie-break for tests. A tenant allow also removes a matching global indicator at compile time (`suppressedByAllow`).

## Output

```jsonc
{
  "schemaVersion": 1,
  "policyVersion": 7,
  "organizationId": "…",
  "generatedAt": "2026-10-28T12:00:00.000Z",
  "rules": [
    {
      "id": 429970366,
      "type": "domain",
      "value": "phase1-block-test.example",
      "action": "block",
      "category": "custom",
      "priority": 2100,
      "source": "tenant",
    },
  ],
  "checksum": "sha256 hex",
  "signature": "reserved (Phase 2), not covered by checksum",
}
```

- **Deterministic rule ids.** FNV-1a over `source|action|type|value`, reduced to `[1, 2^29]`, with linear probing on collision. The same rule keeps the same id across versions, so the extension's DNR diff touches only rules that changed. The cap keeps the DNR ids (`2N`, `2N+1`) below 2^31.
- **Deterministic order** (priority descending, then type, value, action). The same inputs give byte-identical payloads.
- **Cap** of 4,500 rules (`maxRules`). Each block becomes one "unsafe" (redirect) DNR rule, and Chromium allows 5,000 dynamic ones. The lowest-precedence rules are truncated first, and `stats.truncated` reports it.

## Checksum

`checksum = sha256(canonicalJson(payload without checksum and signature))`

Canonical JSON (`packages/shared/src/canonical-json.ts`, mirrored in `CanonicalJson.cs`): keys sorted by UTF-16 code unit, no whitespace, integers only, strings escaped exactly like `JSON.stringify`. Cross-language parity is enforced by `scripts/generate-agent-vectors.ts`, which writes vectors (including tricky Unicode and real compiled policies) that the xUnit suite must reproduce byte for byte. A Vitest check fails if the vectors are stale.

## Versioning

- Publishing creates a new `policy_versions` row (`nextPolicyVersion` = current + 1) and marks the previous one `superseded`.
- A trigger blocks any other change to a version row, so published payloads and checksums are immutable.
- Devices report the version and checksum they hold. The dashboard flags _policy outdated_ when a device lags more than 10 minutes behind the latest publish.

## Enforcement mapping (extension)

| Policy rule        | DNR rule `2N` (main frame)                                                                        | DNR rule `2N+1` (other resources)               |
| ------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| block domain       | redirect to `blocked.html?r=N` (regex substitution carrying the URL, within the 900-regex budget) | block all non-main-frame requests to the domain |
| block exact URL    | redirect (regex `^<escaped url>$`)                                                                | block via `\|url\|` filter                      |
| allow domain / URL | allow all resource types                                                                          | –                                               |

`host_permissions: <all_urls>` is required for redirect rules. The applier pre-checks regexes with `isRegexSupported` and falls back to a non-capturing redirect, so blocking still works.
