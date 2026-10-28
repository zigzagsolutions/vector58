/**
 * Generates cross-language test vectors so the C# agent's canonical JSON and
 * policy checksum stay byte-identical to the TypeScript implementation.
 *
 *   pnpm tsx scripts/generate-agent-vectors.ts
 *
 * Writes services/windows-agent/tests/BrowserSecurity.Agent.Tests/Fixtures/vectors.json.
 * tests/unit/agent-vectors.test.ts fails if the file is stale; the .NET tests
 * fail if C# disagrees with it.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { compilePolicy } from '../packages/policy-engine/src/index';
import { canonicalJson, sha256Hex, type CanonicalValue } from '../packages/shared/src/index';

export const VECTORS_PATH = join(__dirname, '../services/windows-agent/tests/BrowserSecurity.Agent.Tests/Fixtures/vectors.json');

const CANONICAL_INPUTS: CanonicalValue[] = [
  null,
  true,
  0,
  -42,
  9007199254740991,
  '',
  'plain ascii',
  'quote " backslash \\ slash / tab \t newline \n cr \r bs \b ff \f',
  'control \u0000 \u0001 \u001f del \u007f',
  'unicode é ü ñ 中文 עברית',
  'emoji 🛡️ 👩‍💻',
  'separators     and html <script>&amp;</script>',
  [],
  {},
  [1, 'a', null, false, [2, [3]], { z: 1, a: 2 }],
  { b: 1, a: 2, B: 3, _: 4, aa: 5, '10': 6, '9': 7, 'ä': 8, 'é': 9, Z: 10, '': 11 },
  { nested: { y: [{ b: true, a: null }], x: 'v' }, omitted: undefined },
];

export async function generateVectors(): Promise<string> {
  const canonical = await Promise.all(
    CANONICAL_INPUTS.map(async (value) => {
      const c = canonicalJson(value);
      // `input` is plain JSON (undefined members vanish), which is what C# parses.
      return { input: JSON.stringify(value), canonical: c, sha256: await sha256Hex(c) };
    }),
  );

  const policies = [];
  for (const [i, tenantRules] of [
    [],
    [
      { ruleType: 'BLOCK_DOMAIN' as const, normalizedValue: 'phase1-block-test.example', priority: 100, enabled: true, category: 'custom' as const, expiresAt: null },
      { ruleType: 'BLOCK_URL' as const, normalizedValue: 'https://cdn.example/evil.exe?x=1&y="2"', priority: 50, enabled: true, category: 'malicious-download' as const, expiresAt: null },
      { ruleType: 'ALLOW_DOMAIN' as const, normalizedValue: 'false-positive.example', priority: 999, enabled: true, category: 'custom' as const, expiresAt: null },
      { ruleType: 'BLOCK_DOMAIN' as const, normalizedValue: 'xn--bcher-kva.example', priority: 0, enabled: true, category: 'phishing' as const, expiresAt: null },
    ],
  ].entries()) {
    const { payload } = await compilePolicy({
      organizationId: '00000000-0000-4000-a000-00000000000' + (i + 1),
      policyVersion: i + 1,
      generatedAt: '2026-10-28T12:00:00.000Z',
      globalIndicators: [
        { indicatorType: 'domain', normalizedValue: 'global-malware-test.example', threatCategory: 'malware', confidence: 95, status: 'active', expiresAt: null },
        { indicatorType: 'exact_url', normalizedValue: 'https://bad.example/login', threatCategory: 'credential-theft', confidence: 80, status: 'active', expiresAt: null },
      ],
      tenantRules,
    });
    policies.push(payload);
  }

  return JSON.stringify({ generatedBy: 'scripts/generate-agent-vectors.ts', canonical, policies }, null, 2) + '\n';
}

if (process.argv[1]?.endsWith('generate-agent-vectors.ts')) {
  void generateVectors().then((out) => {
    writeFileSync(VECTORS_PATH, out);
    console.log(`wrote ${VECTORS_PATH}`);
  });
}
