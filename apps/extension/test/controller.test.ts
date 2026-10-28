import { NativeMessageSchema } from '@bsp/policy-types';
import { beforeEach, describe, expect, it } from 'vitest';
import { ExtensionController } from '../src/background/controller';
import { reconnectDelayMs } from '../src/background/native-port';
import { EXT_ID, FakePlatform, FakePort, flush, makePolicy, ORIGIN, update } from './fakes';

let platform: FakePlatform;
let ports: FakePort[];
let scheduled: { fn: () => void; ms: number }[];
let badge: string[];
let connectFails: boolean;
let controller: ExtensionController;

const BLOCK_PAGE = { id: EXT_ID, url: `${ORIGIN}/blocked.html?r=1` };

beforeEach(() => {
  platform = new FakePlatform();
  ports = [];
  scheduled = [];
  badge = [];
  connectFails = false;
  controller = new ExtensionController({
    platform,
    connect: () => {
      if (connectFails) throw new Error('Specified native messaging host not found.');
      const p = new FakePort();
      ports.push(p);
      return p;
    },
    client: { browser: 'edge', browserVersion: '131.0.0.0', extensionVersion: '0.1.0' },
    setBadge: (s) => badge.push(s),
    schedule: (fn, ms) => scheduled.push({ fn, ms }),
    random: () => 0.5,
  });
});

const port = () => ports.at(-1)!;
const events = (p: FakePort, type?: string) =>
  p.ofType('SECURITY_EVENT').map((m) => (m as { event: { eventType: string } }).event).filter((e) => !type || e.eventType === type);

describe('ExtensionController', () => {
  it('announces itself on connect and every outgoing message matches the shared protocol schema', async () => {
    await controller.ensureConnected();
    const p = port();
    expect(p.ofType('CLIENT_HEALTH')).toHaveLength(1);
    expect(p.ofType('REQUEST_POLICY')[0]).toMatchObject({ currentVersion: null });
    expect(events(p, 'EXTENSION_CONNECTED')).toHaveLength(1);
    for (const m of p.sent) expect(NativeMessageSchema.safeParse(m).success).toBe(true);
    expect(badge.at(-1)).toBe('ok');
  });

  it('ensureConnected is idempotent', async () => {
    await controller.ensureConnected();
    await controller.ensureConnected();
    expect(ports).toHaveLength(1);
  });

  it('applies POLICY_UPDATE, replies POLICY_STATUS and emits POLICY_APPLIED', async () => {
    await controller.ensureConnected();
    await controller.onNativeMessage(update(await makePolicy(1)));
    const p = port();
    expect(p.ofType('POLICY_STATUS').at(-1)).toMatchObject({ status: 'applied', policyVersion: 1 });
    expect(events(p, 'POLICY_APPLIED')).toHaveLength(1);
    for (const m of p.sent) expect(NativeMessageSchema.safeParse(m).success).toBe(true);
  });

  it('reports POLICY_FAILED for invalid policies', async () => {
    await controller.ensureConnected();
    const p1 = await makePolicy(1);
    await controller.onNativeMessage(update({ ...p1, checksum: '0'.repeat(64) }));
    expect(port().ofType('POLICY_STATUS').at(-1)).toMatchObject({ status: 'failed' });
    expect(events(port(), 'POLICY_FAILED')).toHaveLength(1);
  });

  it('keeps rules, shows degraded and queues events when the host disconnects; flushes on reconnect', async () => {
    await controller.ensureConnected();
    await controller.onNativeMessage(update(await makePolicy(1)));
    const rulesBefore = platform.rules.size;
    port().hostExit();
    await flush();
    expect(controller.isConnected).toBe(false);
    expect(badge.at(-1)).toBe('degraded');
    expect(platform.rules.size).toBe(rulesBefore);
    expect((await controller.state.health()).nativeConnected).toBe(false);

    // A block happens while the agent is unreachable.
    const ruleId = (await makePolicy(1)).rules.find((r) => r.value === 'phase1-block-test.example')!.id;
    await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId, url: 'https://phase1-block-test.example/x' }, BLOCK_PAGE, EXT_ID);
    const queued = await controller.state.queue();
    expect(queued.map((e) => e.eventType)).toEqual(['EXTENSION_DISCONNECTED', 'URL_BLOCKED']);

    // Backoff reconnect is scheduled and delivers the queue.
    expect(scheduled).toHaveLength(1);
    scheduled[0]!.fn();
    await flush();
    await flush();
    const p2 = port();
    expect(ports).toHaveLength(2);
    expect(p2.ofType('REQUEST_POLICY')[0]).toMatchObject({ currentVersion: 1 });
    expect(events(p2).map((e) => e.eventType)).toEqual(['EXTENSION_CONNECTED', 'EXTENSION_DISCONNECTED', 'URL_BLOCKED']);
    expect(await controller.state.queue()).toHaveLength(0);
  });

  it('backs off when the host is missing', async () => {
    connectFails = true;
    await controller.ensureConnected();
    expect((await controller.state.health()).lastError).toMatch(/not found/);
    expect(scheduled).toHaveLength(1);
    scheduled[0]!.fn();
    await flush();
    expect(scheduled[1]!.ms).toBeGreaterThan(scheduled[0]!.ms);
    expect(reconnectDelayMs(20, () => 0.5)).toBe(60_000);
  });

  it('answers COLLECT_HISTORY as unsupported in Phase 1 and never reads history', async () => {
    await controller.ensureConnected();
    await controller.onNativeMessage({
      type: 'COLLECT_HISTORY',
      commandId: '33333333-3333-4333-8333-333333333333',
      startTime: '2026-10-27T00:00:00.000Z',
      endTime: '2026-10-28T00:00:00.000Z',
    });
    expect(port().ofType('COLLECT_HISTORY')[0]).toMatchObject({ result: { status: 'unsupported' } });
  });

  it('answers DIAGNOSTIC_REQUEST with local state', async () => {
    await controller.ensureConnected();
    await controller.onNativeMessage(update(await makePolicy(1)));
    await controller.onNativeMessage({ type: 'DIAGNOSTIC_REQUEST', requestId: 'diag-1' });
    expect(port().ofType('DIAGNOSTIC_REQUEST')[0]).toMatchObject({
      requestId: 'diag-1',
      response: { browser: 'edge', policyVersion: 1, dnrRuleCount: platform.rules.size },
    });
  });

  it('ignores unknown or malformed native messages', async () => {
    await controller.ensureConnected();
    const before = port().sent.length;
    await controller.onNativeMessage({ type: 'RUN_SCRIPT', code: 'alert(1)' });
    await controller.onNativeMessage('garbage');
    expect(port().sent.length).toBe(before);
  });
});

describe('block page reports', () => {
  let ruleId: number;
  beforeEach(async () => {
    await controller.ensureConnected();
    const p = await makePolicy(1);
    ruleId = p.rules.find((r) => r.value === 'phase1-block-test.example')!.id;
    await controller.onNativeMessage(update(p));
  });

  it('emits a verified URL_BLOCKED event', async () => {
    const res = await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId, url: 'https://www.phase1-block-test.example/login?x=1' }, BLOCK_PAGE, EXT_ID);
    expect(res).toEqual({ domain: 'www.phase1-block-test.example', category: 'custom', ruleId });
    const [e] = events(port(), 'URL_BLOCKED');
    expect(e).toMatchObject({ url: 'https://www.phase1-block-test.example/login?x=1', domain: 'www.phase1-block-test.example', ruleId, policyVersion: 1, browser: 'edge' });
  });

  it('rejects reports from web pages or other extensions', async () => {
    const msg = { type: 'BLOCK_PAGE_REPORT', ruleId, url: 'https://phase1-block-test.example/' };
    expect(await controller.onBlockPageReport(msg, { id: 'otherextension', url: `${ORIGIN}/blocked.html` }, EXT_ID)).toBeNull();
    expect(await controller.onBlockPageReport(msg, { id: EXT_ID, url: 'https://evil.example/' }, EXT_ID)).toBeNull();
    expect(await controller.onBlockPageReport(msg, { id: EXT_ID, url: `${ORIGIN}/popup.html` }, EXT_ID)).toBeNull();
    expect(events(port(), 'URL_BLOCKED')).toHaveLength(0);
  });

  it('rejects forged reports that do not match the policy', async () => {
    // URL not covered by the rule
    expect(await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId, url: 'https://innocent.example/' }, BLOCK_PAGE, EXT_ID)).toBeNull();
    // unknown rule
    expect(await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId: 999999, url: null }, BLOCK_PAGE, EXT_ID)).toBeNull();
    // allow rule
    const allowId = (await makePolicy(1)).rules.find((r) => r.action === 'allow')!.id;
    expect(await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId: allowId, url: null }, BLOCK_PAGE, EXT_ID)).toBeNull();
    expect(events(port(), 'URL_BLOCKED')).toHaveLength(0);
  });

  it('reports without a captured URL using the rule value', async () => {
    const res = await controller.onBlockPageReport({ type: 'BLOCK_PAGE_REPORT', ruleId, url: null }, BLOCK_PAGE, EXT_ID);
    expect(res?.domain).toBe('phase1-block-test.example');
    expect(events(port(), 'URL_BLOCKED')[0]).toMatchObject({ url: 'https://phase1-block-test.example/', details: { urlCaptured: false } });
  });

  it('deduplicates reloads of the block page', async () => {
    const msg = { type: 'BLOCK_PAGE_REPORT', ruleId, url: 'https://phase1-block-test.example/' };
    await controller.onBlockPageReport(msg, BLOCK_PAGE, EXT_ID);
    await controller.onBlockPageReport(msg, BLOCK_PAGE, EXT_ID);
    expect(events(port(), 'URL_BLOCKED')).toHaveLength(1);
    platform.clock = new Date(platform.clock.getTime() + 60_000);
    await controller.onBlockPageReport(msg, BLOCK_PAGE, EXT_ID);
    expect(events(port(), 'URL_BLOCKED')).toHaveLength(2);
  });
});

describe('event queue', () => {
  it('does not lose events enqueued concurrently and stays bounded', async () => {
    const { MAX_QUEUED_EVENTS } = await import('../src/background/state');
    await Promise.all(Array.from({ length: 50 }, () => controller.emit('AGENT_HEARTBEAT', {})));
    expect(await controller.state.queue()).toHaveLength(50);
    await Promise.all(Array.from({ length: MAX_QUEUED_EVENTS }, () => controller.emit('AGENT_HEARTBEAT', {})));
    expect(await controller.state.queue()).toHaveLength(MAX_QUEUED_EVENTS);
  });
});
