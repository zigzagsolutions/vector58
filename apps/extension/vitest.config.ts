import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { __BROWSER__: JSON.stringify('chrome') },
  test: { include: ['src/**/*.test.ts', 'test/**/*.test.ts'], environment: 'node' },
});
