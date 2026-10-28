import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Database-backed suites: tenant isolation (RLS) and API integration tests.
 * globalSetup rebuilds TEST_DATABASE_URL from migrations + seed before the run.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@/': fileURLToPath(new URL('../apps/admin/src/', import.meta.url)),
      'server-only': fileURLToPath(new URL('./fixtures/server-only.ts', import.meta.url)),
    },
  },
  test: {
    include: ['tenant-isolation/**/*.test.ts', 'integration/**/*.test.ts'],
    globalSetup: ['./fixtures/global-setup.ts'],
    setupFiles: ['./fixtures/env.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
