import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../../', import.meta.url));

function trackedFiles(): string[] {
  try {
    return execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

describe('secret hygiene', () => {
  const files = trackedFiles();

  it('no service-role key or secret env var is referenced from client-side code', () => {
    const clientFiles = files.filter(
      (f) =>
        (f.startsWith('apps/admin/src/') && !f.startsWith('apps/admin/src/server/') && /\.(tsx?|mjs)$/.test(f)) ||
        f.startsWith('apps/extension/src/'),
    );
    const offenders = clientFiles.filter((f) => {
      const src = readFileSync(`${root}${f}`, 'utf8');
      const isServerModule = /^import 'server-only';/m.test(src) || /^'use server';/m.test(src);
      return !isServerModule && /SUPABASE_SECRET_KEY|SERVICE_ROLE|DATABASE_URL|DEVICE_TOKEN_PEPPER/.test(src);
    });
    expect(offenders).toEqual([]);
  });

  it('no JWT-looking or sb_secret keys are committed', () => {
    const offenders = files.filter((f) => {
      if (/\.(png|ico|jpg|lock|snk)$/.test(f) || f === 'pnpm-lock.yaml') return false;
      const src = readFileSync(`${root}${f}`, 'utf8');
      return /eyJhbGciOi[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/.test(src) || /sb_secret_[A-Za-z0-9]{10,}/.test(src);
    });
    expect(offenders).toEqual([]);
  });
});
