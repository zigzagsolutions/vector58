/**
 * Phase 1 acceptance flow, end to end:
 *   enroll agent -> browser connects -> admin blocks a domain and publishes ->
 *   agent pulls and verifies -> native messaging -> extension applies DNR ->
 *   navigation lands on the block page -> URL_BLOCKED reaches the tenant's
 *   event log (and only that tenant's) -> commands round-trip -> rule removal
 *   unblocks -> protection survives a control-plane outage and an agent restart.
 */
import { chromium, type BrowserContext, type Worker } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as api from '@/server/api/v1';
import { closePool as closeAppPool } from '@/server/db';
import { asService, closePool, ORG_ACME, ORG_INTERNAL, USERS } from '../fixtures/db';
import { body, depsFor, params, req } from '../fixtures/api';
import { EXTENSION_ID, ROOT, Stack, sleep, waitFor } from './stack';

/** Extension APIs used inside the service worker via sw.evaluate(). */
declare const chrome: {
  storage: { local: { get(keys: string[]): Promise<Record<string, unknown>> } };
  declarativeNetRequest: { getDynamicRules(): Promise<unknown[]> };
};

const BLOCKED = 'phase1-block-test.example';
const secAdmin = depsFor(USERS.internalSecAdmin);
const acmeOwner = depsFor(USERS.acmeOwner);
const stack = new Stack(process.env.TEST_DATABASE_URL!);
const userDataDir = mkdtempSync(join(tmpdir(), 'bsp-e2e-chromium-'));
let context: BrowserContext;
let sw: Worker;
let deviceId: string;
let ruleId: string;

async function publish() {
  return body<{ versionNumber: number }>(
    await api.orgPublishPolicy(req('POST', '/x'), params({ id: ORG_INTERNAL, policyId: '00000000-0000-4f10-8000-000000000001' }), secAdmin),
  );
}

/** Navigates and reports whether the extension's block page was shown. */
async function visit(url: string): Promise<{ blocked: boolean; text: string }> {
  const page = await context.newPage();
  try {
    await page.goto(url, { timeout: 10_000 }).catch(() => undefined); // unresolvable hosts error when not blocked
    await sleep(300);
    const blocked = page.url().startsWith(`chrome-extension://${EXTENSION_ID}/blocked.html`);
    const text = blocked ? ((await page.textContent('main')) ?? '') : '';
    return { blocked, text };
  } finally {
    await page.close();
  }
}

const extensionState = () =>
  sw.evaluate(async () => {
    const s = await chrome.storage.local.get(['bsp.policy', 'bsp.health']);
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return {
      policyVersion: (s['bsp.policy'] as { policyVersion?: number } | undefined)?.policyVersion ?? null,
      nativeConnected: (s['bsp.health'] as { nativeConnected?: boolean } | undefined)?.nativeConnected ?? false,
      dnrRuleCount: rules.length,
    };
  });

async function launchBrowser() {
  const ext = join(ROOT, 'apps/extension/dist/chrome');
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    // Lets a preinstalled Chromium be used when it differs from the pinned Playwright build.
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  sw = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
}

beforeAll(async () => {
  stack.checkPrerequisites();
  stack.buildAgent();
  await stack.startWeb();
  stack.writeEnrollmentToken('dev-internal-enroll-token-0000000001');
  stack.startAgent();
  stack.installNativeHost(userDataDir);
});

afterAll(async () => {
  await context?.close();
  await stack.stopAll();
  rmSync(userDataDir, { recursive: true, force: true });
  await closePool();
  await closeAppPool();
});

describe('Phase 1 end-to-end blocking flow', () => {
  it('enrolls the agent into the tenant that issued the token', async () => {
    deviceId = await waitFor('device enrollment', async () => {
      const r = await asService((c) => c.query(`select id from public.devices where organization_id = $1 and enrolled_at > now() - interval '10 minutes'`, [ORG_INTERNAL]));
      return r.rows[0]?.id as string | undefined;
    }, 60_000);
    expect(deviceId).toBeTruthy();
  });

  it('connects Chromium through the .NET native host and reports the browser in heartbeats', async () => {
    await launchBrowser();
    await waitFor('extension connected to agent', async () => (await extensionState()).nativeConnected, 30_000);
    const client = await waitFor('browser client in heartbeat', async () => {
      const r = await asService((c) => c.query(`select browser, extension_version from public.browser_clients where device_id = $1`, [deviceId]));
      return r.rows[0];
    }, 30_000);
    expect(client).toMatchObject({ browser: 'chrome', extension_version: '0.1.0' });
    expect((await visit(`https://${BLOCKED}/`)).blocked).toBe(false);
  });

  it('blocks the domain after a tenant admin adds a rule and publishes', async () => {
    const created = await body<{ rule: { id: string } }>(
      await api.orgCreateRule(req('POST', '/x', { ruleType: 'BLOCK_DOMAIN', value: BLOCKED, category: 'phishing' }), params({ id: ORG_INTERNAL }), secAdmin),
    );
    ruleId = created.rule.id;
    const v = await publish();

    await waitFor('extension applied new policy', async () => (await extensionState()).policyVersion === v.versionNumber, 30_000);
    const res = await visit(`https://www.${BLOCKED}/login?next=1`);
    expect(res.blocked).toBe(true);
    expect(res.text).toContain('This site has been blocked');
    expect(res.text).toContain(`www.${BLOCKED}`);
    expect(res.text).toContain('Phishing');
    // Global threat intelligence is enforced alongside tenant rules.
    expect((await visit('https://global-malware-test.example/')).blocked).toBe(true);
    // Another tenant's rule is not.
    expect((await visit('https://acme-only-block.example/')).blocked).toBe(false);
  });

  it('records URL_BLOCKED for this tenant only', async () => {
    const event = await waitFor('URL_BLOCKED event', async () => {
      const list = await body<{ events: { domain: string; url: string; browser: string; deviceId: string; policyVersion: number }[] }>(
        await api.orgEvents(req('GET', '/x?eventType=URL_BLOCKED'), params({ id: ORG_INTERNAL }), secAdmin),
      );
      return list.events.find((e) => e.domain === `www.${BLOCKED}`);
    }, 30_000);
    expect(event).toMatchObject({ url: `https://www.${BLOCKED}/login?next=1`, browser: 'chrome', deviceId });

    await expect(api.orgEvents(req('GET', '/x'), params({ id: ORG_INTERNAL }), acmeOwner)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const acme = await body<{ events: { domain: string | null }[] }>(await api.orgEvents(req('GET', '/x'), params({ id: ORG_ACME }), acmeOwner));
    expect(acme.events.some((e) => e.domain?.includes(BLOCKED))).toBe(false);
  });

  it('executes diagnostics commands, including the extension’s own report', async () => {
    const cmd = await body<{ id: string }>(
      await api.orgCreateCommand(req('POST', '/x', { deviceId, commandType: 'COLLECT_DIAGNOSTICS' }), params({ id: ORG_INTERNAL }), secAdmin),
    );
    const done = await waitFor('command completed', async () => {
      const r = await asService((c) => c.query(`select status, result from public.endpoint_commands where id = $1`, [cmd.id]));
      return r.rows[0]?.status === 'COMPLETED' ? r.rows[0] : null;
    }, 30_000);
    expect(done.result.agent.version).toBe('0.1.0');
    expect(done.result.extensions[0].response).toMatchObject({ browser: 'chrome', dnrRuleCount: expect.any(Number) });
  });

  it('unblocks after the rule is removed and a new version is published', async () => {
    await api.orgDeleteRule(req('DELETE', '/x'), params({ id: ORG_INTERNAL, ruleId }), secAdmin);
    const v = await publish();
    await waitFor('extension applied removal', async () => (await extensionState()).policyVersion === v.versionNumber, 30_000);
    expect((await visit(`https://${BLOCKED}/`)).blocked).toBe(false);
  });

  it('keeps enforcing the last-known-good policy through a control-plane outage and an agent restart', async () => {
    await api.orgCreateRule(req('POST', '/x', { ruleType: 'BLOCK_DOMAIN', value: BLOCKED }), params({ id: ORG_INTERNAL }), secAdmin);
    const v = await publish();
    await waitFor('extension applied re-block', async () => (await extensionState()).policyVersion === v.versionNumber, 30_000);

    await stack.web.stop(); // cloud outage
    await sleep(3000);
    expect((await visit(`https://${BLOCKED}/`)).blocked).toBe(true);

    await stack.agent.stop(); // agent down: extension degrades but keeps its rules
    await waitFor('extension notices agent loss', async () => !(await extensionState()).nativeConnected, 30_000);
    expect((await visit(`https://${BLOCKED}/`)).blocked).toBe(true);

    stack.startAgent(); // restarts offline from its verified cache
    await waitFor('extension reconnects to restarted agent', async () => (await extensionState()).nativeConnected, 90_000, 500);
    const state = await extensionState();
    expect(state.policyVersion).toBe(v.versionNumber);
    expect((await visit(`https://${BLOCKED}/`)).blocked).toBe(true);
  });
});
