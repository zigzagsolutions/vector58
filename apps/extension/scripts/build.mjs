/* global process, console */
// Builds unpacked Chrome and Edge extensions into dist/<browser>.
//
//   node scripts/build.mjs                 dev build, stable dev extension ID
//   node scripts/build.mjs --release       no "key": the store assigns the ID
//   BSP_EXTENSION_VERSION=1.2.3            override manifest version
import { build } from 'esbuild';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const release = process.argv.includes('--release');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const version = process.env.BSP_EXTENSION_VERSION ?? pkg.version;
const devKey = (await readFile(join(root, 'static/dev-public-key.txt'), 'utf8')).trim();

const BROWSERS = {
  chrome: { name: 'Vector58 Browser Security', minimum: { minimum_chrome_version: '120' } },
  edge: { name: 'Vector58 Browser Security for Edge', minimum: { minimum_chrome_version: '120' } },
};

function manifest(browser) {
  const b = BROWSERS[browser];
  return {
    manifest_version: 3,
    name: b.name,
    short_name: 'Browser Security',
    description:
      "Enforces your organization's browser security policy. Managed by your IT department.",
    version,
    ...b.minimum,
    ...(release ? {} : { key: devKey }),
    background: { service_worker: 'service-worker.js', type: 'module' },
    // declarativeNetRequest: enforce policy. nativeMessaging: talk to the
    // Windows agent. storage: last-known-good policy metadata + event queue.
    // alarms: reconnect backstop. <all_urls> host access is required for
    // redirect rules that send blocked navigations to blocked.html.
    permissions: ['declarativeNetRequest', 'nativeMessaging', 'storage', 'alarms'],
    host_permissions: ['<all_urls>'],
    action: { default_title: 'Browser Security', default_popup: 'popup.html' },
    web_accessible_resources: [{ resources: ['blocked.html'], matches: ['<all_urls>'] }],
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'",
    },
  };
}

for (const browser of Object.keys(BROWSERS)) {
  const out = join(root, 'dist', browser);
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await build({
    entryPoints: {
      'service-worker': join(root, 'src/background/service-worker.ts'),
      blocked: join(root, 'src/blocked/blocked.ts'),
      popup: join(root, 'src/popup/popup.ts'),
    },
    outdir: out,
    bundle: true,
    format: 'esm',
    target: 'chrome120',
    platform: 'browser',
    minify: release,
    sourcemap: release ? false : 'linked',
    legalComments: 'none',
    define: { __BROWSER__: JSON.stringify(browser) },
    logLevel: 'warning',
  });
  for (const f of [
    'blocked/blocked.html',
    'blocked/blocked.css',
    'popup/popup.html',
    'popup/popup.css',
  ]) {
    await cp(join(root, 'src', f), join(out, f.split('/')[1]));
  }
  await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest(browser), null, 2) + '\n');
  console.log(`built ${browser} -> ${out}${release ? ' (release)' : ''}`);
}
