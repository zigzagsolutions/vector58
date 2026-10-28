import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { chmodSync, createWriteStream, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const ARTIFACTS = join(ROOT, 'test-results', 'e2e');
export const EXTENSION_ID = 'ikgimjohebonbmlfdngiiebaadojbdmp';
const AGENT_DIR = join(ROOT, 'services/windows-agent');

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function waitFor<T>(what: string, fn: () => Promise<T | null | undefined | false>, timeoutMs = 30_000, everyMs = 250): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await sleep(everyMs);
  }
  throw new Error(`Timed out waiting for ${what}${last ? `: ${String(last)}` : ''}`);
}

class Proc {
  child: ChildProcess | null = null;
  constructor(
    readonly name: string,
    private readonly cmd: string,
    private readonly args: string[],
    private readonly opts: { cwd: string; env: NodeJS.ProcessEnv },
  ) {}
  start() {
    mkdirSync(ARTIFACTS, { recursive: true });
    const log = createWriteStream(join(ARTIFACTS, `${this.name}.log`), { flags: 'a' });
    this.child = spawn(this.cmd, this.args, { cwd: this.opts.cwd, env: this.opts.env, stdio: ['ignore', 'pipe', 'pipe'] });
    this.child.stdout!.pipe(log);
    this.child.stderr!.pipe(log);
    return this;
  }
  async stop() {
    const c = this.child;
    if (!c || c.exitCode !== null) return;
    const exited = new Promise((r) => c.once('exit', r));
    c.kill('SIGTERM');
    await Promise.race([exited, sleep(10_000)]);
    if (c.exitCode === null) c.kill('SIGKILL');
    this.child = null;
  }
}

export class Stack {
  readonly port = 3210;
  readonly baseUrl = `http://localhost:${this.port}`;
  readonly work = mkdtempSync(join(tmpdir(), 'bsp-e2e-'));
  readonly agentData = join(this.work, 'agent-data');
  readonly browserPipe = `bsp-e2e-browser-${process.pid}`;
  readonly statusPipe = `bsp-e2e-status-${process.pid}`;
  web!: Proc;
  agent!: Proc;

  constructor(readonly databaseUrl: string) {}

  checkPrerequisites() {
    const missing: string[] = [];
    if (!existsSync(join(ROOT, 'apps/admin/.next/BUILD_ID'))) missing.push('admin build (pnpm --filter @bsp/admin build)');
    if (!existsSync(join(ROOT, 'apps/extension/dist/chrome/manifest.json'))) missing.push('extension build (pnpm --filter @bsp/extension build)');
    try {
      execFileSync('dotnet', ['--version'], { stdio: 'ignore' });
    } catch {
      missing.push('.NET 10 SDK');
    }
    if (missing.length) throw new Error(`E2E prerequisites missing: ${missing.join(', ')}`);
  }

  buildAgent() {
    for (const project of ['src/BrowserSecurity.Agent.Service', 'src/BrowserSecurity.Agent.NativeMessaging']) {
      execFileSync('dotnet', ['build', project, '-c', 'Debug', '--nologo', '-v', 'q'], { cwd: AGENT_DIR, stdio: 'inherit' });
    }
  }

  agentDll = () => join(AGENT_DIR, 'src/BrowserSecurity.Agent.Service/bin/Debug/net10.0/BrowserSecurity.Agent.Service.dll');
  hostDll = () => join(AGENT_DIR, 'src/BrowserSecurity.Agent.NativeMessaging/bin/Debug/net10.0/BrowserSecurity.NativeHost.dll');

  async startWeb() {
    this.web = new Proc('web', join(ROOT, 'apps/admin/node_modules/.bin/next'), ['start', '-p', String(this.port)], {
      cwd: join(ROOT, 'apps/admin'),
      env: {
        ...process.env,
        NODE_ENV: 'production',
        DATABASE_URL: this.databaseUrl,
        NEXT_PUBLIC_SUPABASE_URL: 'http://127.0.0.1:9',
        NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: 'e2e-not-used',
        NEXT_PUBLIC_APP_BASE_URL: this.baseUrl,
        TRUSTED_PROXY_MODE: 'none',
        CRON_SECRET: 'e2e-cron-secret-0123456789abcdef0123456789',
      },
    }).start();
    await waitFor('web server', async () => (await fetch(`${this.baseUrl}/api/v1/health`)).ok, 60_000, 500);
  }

  writeEnrollmentToken(token: string) {
    mkdirSync(this.agentData, { recursive: true, mode: 0o700 });
    writeFileSync(join(this.agentData, 'enrollment.token'), token, { mode: 0o600 });
  }

  startAgent() {
    this.agent = new Proc('agent', 'dotnet', [this.agentDll()], {
      cwd: this.work,
      env: {
        ...process.env,
        DOTNET_ENVIRONMENT: 'Development',
        BSP_Agent__ApiBaseUrl: this.baseUrl,
        BSP_Agent__PortalUrl: this.baseUrl,
        BSP_Agent__AllowInsecureLocalhost: 'true',
        BSP_Agent__AllowUnprotectedSecretStorage: 'true',
        BSP_Agent__DataDirectory: this.agentData,
        BSP_Agent__BrowserPipeName: this.browserPipe,
        BSP_Agent__StatusPipeName: this.statusPipe,
        BSP_Agent__HeartbeatIntervalSeconds: '2',
        BSP_Agent__PolicyPollIntervalSeconds: '3',
        BSP_Agent__CommandPollIntervalSeconds: '2',
        BSP_Agent__EventFlushIntervalSeconds: '1',
        BSP_Agent__AllowedExtensionIds__0: EXTENSION_ID,
      },
    }).start();
  }

  /** Chromium's per-profile native messaging manifest, pointing at a wrapper that runs the .NET host. */
  installNativeHost(userDataDir: string) {
    const wrapper = join(this.work, 'native-host.sh');
    writeFileSync(wrapper, `#!/bin/sh\nexport BSP_AGENT_BROWSER_PIPE='${this.browserPipe}'\nexec dotnet '${this.hostDll()}' "$@"\n`);
    chmodSync(wrapper, 0o755);
    mkdirSync(join(userDataDir, 'NativeMessagingHosts'), { recursive: true });
    writeFileSync(
      join(userDataDir, 'NativeMessagingHosts', 'com.vector58.browser_security.json'),
      JSON.stringify({
        name: 'com.vector58.browser_security',
        description: 'Vector58 Browser Security native host (e2e)',
        path: wrapper,
        type: 'stdio',
        allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
      }),
    );
  }

  async stopAll() {
    await this.agent?.stop();
    await this.web?.stop();
    rmSync(this.work, { recursive: true, force: true });
  }
}
