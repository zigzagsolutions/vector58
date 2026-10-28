// Environment for integration tests that exercise the admin server modules directly.
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgres://postgres@127.0.0.1:54329/bsp_test';
process.env.NEXT_PUBLIC_APP_BASE_URL = 'http://localhost:3000';
process.env.TRUSTED_PROXY_MODE = 'none';
