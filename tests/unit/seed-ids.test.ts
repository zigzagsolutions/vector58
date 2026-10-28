import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

/** Seeded ids flow through API params validated with z.uuid(); they must be RFC 9562 compliant. */
describe('seed data ids', () => {
  it('are valid UUIDs (version 1-8, variant 10xx)', () => {
    const seed = readFileSync(
      fileURLToPath(new URL('../../supabase/seed.sql', import.meta.url)),
      'utf8',
    );
    const ids = new Set(
      seed.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g) ?? [],
    );
    ids.delete('00000000-0000-0000-0000-000000000000'); // auth.users.instance_id convention
    expect(ids.size).toBeGreaterThan(10);
    const invalid = [...ids].filter((id) => !z.uuid().safeParse(id).success);
    expect(invalid).toEqual([]);
  });
});
