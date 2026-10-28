import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres@127.0.0.1:54329/bsp_test';

export default function setup() {
  const script = fileURLToPath(new URL('../../scripts/db-reset.sh', import.meta.url));
  execFileSync('bash', [script], {
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
    stdio: 'inherit',
  });
  process.env.TEST_DATABASE_URL = TEST_DATABASE_URL;
}
