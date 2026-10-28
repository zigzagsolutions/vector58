import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { generateVectors, VECTORS_PATH } from '../../scripts/generate-agent-vectors';

describe('C# agent parity vectors', () => {
  it('are up to date (run `pnpm tsx scripts/generate-agent-vectors.ts` if this fails)', async () => {
    expect(readFileSync(VECTORS_PATH, 'utf8')).toBe(await generateVectors());
  });
});
