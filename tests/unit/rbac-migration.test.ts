import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generateRbacSql } from '../../scripts/generate-rbac-sql';

describe('RBAC migration is generated from the TypeScript catalog', () => {
  it('is up to date (run scripts/generate-rbac-sql.ts if this fails)', () => {
    const file = fileURLToPath(
      new URL('../../supabase/migrations/20261028000009_rbac_reference_data.sql', import.meta.url),
    );
    expect(readFileSync(file, 'utf8')).toBe(generateRbacSql());
  });
});
