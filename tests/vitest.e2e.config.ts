import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Full-stack end-to-end test: real Postgres, the built Next.js server, the
 * .NET agent service and native messaging host, and Chromium with the built
 * extension. Admin actions call the same API handlers the portal uses
 * (Supabase Auth is not available locally); everything device-side goes over
 * real HTTP, named pipes and native messaging.
 *
 * Prerequisites: `pnpm build` (admin + extension), .NET 10 SDK, a local
 * Postgres (scripts/local-postgres.sh), and Playwright's Chromium.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@/': fileURLToPath(new URL('../apps/admin/src/', import.meta.url)),
      'server-only': fileURLToPath(new URL('./fixtures/server-only.ts', import.meta.url)),
    },
  },
  test: {
    include: ['browser-e2e/**/*.test.ts'],
    globalSetup: ['./browser-e2e/global-setup.ts'],
    setupFiles: ['./fixtures/env.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 300_000,
  },
});
