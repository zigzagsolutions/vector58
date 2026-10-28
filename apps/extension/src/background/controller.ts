import { NATIVE_PROTOCOL_VERSION, NativeMessageSchema, type NativeMessage, type ReportedSecurityEvent, type SecurityEventType } from '@bsp/policy-types';
import { applyPolicyUpdate } from './policy-applier';
import { buildUrlBlockedEvent, ReportDeduper, type ClientInfo } from './block-report';
import { reconnectDelayMs, type NativeConnector, type NativePort } from './native-port';
import type { ExtensionPlatform } from './platform';
import { ExtensionState } from './state';
import { BLOCK_PAGE_PATH } from './rule-converter';

export interface ControllerDeps {
  readonly platform: ExtensionPlatform;
  readonly connect: NativeConnector;
  readonly client: Omit<ClientInfo, 'clientId'>;
  /** Reflect degraded/healthy state in the toolbar; optional in tests. */
  readonly setBadge?: (state: 'ok' | 'degraded') => void;
  readonly schedule?: (fn: () => void, ms: number) => void;
  readonly random?: () => number;
}

/** Message sent by blocked.html to the service worker. */
export interface BlockReportMessage {
  readonly type: 'BLOCK_PAGE_REPORT';
  readonly ruleId: number;
  readonly url: string | null;
}

export interface BlockReportResult {
  readonly domain: string | null;
  readonly category: string | null;
  readonly ruleId: number | null;
}

export interface MessageSenderLike {
  readonly id?: string;
  readonly url?: string;
}

/**
 * Owns the native messaging connection and routes messages between the
 * Windows agent and the enforcement layer.
 *
 * Failure behaviour (spec): if native messaging is unavailable, previously
 * applied DNR rules stay in force, the toolbar shows a degraded state, and
 * events are queued locally (bounded) until the host reconnects.
 */
export class ExtensionController {
  readonly state: ExtensionState;
  private port: NativePort | null = null;
  private connected = false;
  private attempt = 0;
  private reconnectPending = false;
  private readonly deduper = new ReportDeduper();

  constructor(private readonly deps: ControllerDeps) {
    this.state = new ExtensionState(deps.platform);
  }

  get isConnected() {
    return this.connected;
  }

  /** Idempotent: safe to call from onStartup, onInstalled and the keepalive alarm. */
  async ensureConnected(): Promise<void> {
    if (this.port) return;
    let port: NativePort;
    try {
      port = this.deps.connect();
    } catch (e) {
      await this.onDisconnected((e as Error).message ?? 'connectNative failed');
      return;
    }
    this.port = port;
    port.onMessage((m) => void this.onNativeMessage(m));
    port.onDisconnect((err) => {
      if (this.port === port) void this.onDisconnected(err);
    });
    await this.onConnected();
  }

  private async onConnected() {
    this.connected = true;
    this.attempt = 0;
    await this.state.updateHealth({ nativeConnected: true, lastError: null });
    this.deps.setBadge?.('ok');
    const policy = await this.state.getPolicy();
    this.post({ type: 'CLIENT_HEALTH', client: await this.clientSnapshot() });
    this.post({ type: 'REQUEST_POLICY', currentVersion: policy?.policyVersion ?? null });
    await this.emit('EXTENSION_CONNECTED', {});
    await this.flushQueue();
  }

  private async onDisconnected(error: string | null) {
    const wasConnected = this.connected;
    this.port = null;
    this.connected = false;
    await this.state.updateHealth({ nativeConnected: false, lastError: error ?? 'Native host disconnected' });
    this.deps.setBadge?.('degraded');
    // Queued and delivered when the host comes back. Rules stay in force.
    if (wasConnected) await this.emit('EXTENSION_DISCONNECTED', { error });
    this.scheduleReconnect();
  }

  private scheduleReconnect() {
    if (this.reconnectPending || !this.deps.schedule) return;
    this.reconnectPending = true;
    const delay = reconnectDelayMs(this.attempt++, this.deps.random);
    this.deps.schedule(() => {
      this.reconnectPending = false;
      void this.ensureConnected();
    }, delay);
  }

  private post(message: NativeMessage): boolean {
    if (!this.port || !this.connected) return false;
    try {
      this.port.postMessage({ ...message, protocolVersion: NATIVE_PROTOCOL_VERSION });
      return true;
    } catch {
      return false;
    }
  }

  async onNativeMessage(raw: unknown): Promise<void> {
    const type = (raw as { type?: unknown } | null)?.type;
    if (type === 'POLICY_UPDATE') {
      // Validated in depth (schema + checksum + rollback) by the applier.
      const outcome = await applyPolicyUpdate(raw, this.deps.platform, this.state);
      await this.state.updateHealth({ lastPolicyStatus: outcome.status.status, ...(outcome.error ? { lastError: outcome.error } : {}) });
      this.post(outcome.status);
      if (outcome.status.status === 'applied') {
        await this.emit('POLICY_APPLIED', { ruleCount: outcome.status.ruleCount }, outcome.status.policyVersion);
        this.post({ type: 'CLIENT_HEALTH', client: await this.clientSnapshot() });
      } else if (outcome.status.status === 'failed') {
        await this.emit('POLICY_FAILED', { error: outcome.error ?? 'unknown' }, outcome.status.policyVersion);
      }
      return;
    }

    const parsed = NativeMessageSchema.safeParse(raw);
    if (!parsed.success) {
      await this.state.updateHealth({ lastError: `Ignored invalid native message (${String(type)})` });
      return;
    }
    const msg = parsed.data;
    switch (msg.type) {
      case 'COLLECT_HISTORY':
        // Phase 1: the extension does not read browsing history. The agent
        // records the command as NOT_SUPPORTED. See docs/incident-response.md.
        this.post({ ...msg, result: { status: 'unsupported', error: 'History collection is not supported in Phase 1' } });
        return;
      case 'DIAGNOSTIC_REQUEST': {
        const policy = await this.state.getPolicy();
        const health = await this.state.health();
        this.post({
          type: 'DIAGNOSTIC_REQUEST',
          requestId: msg.requestId,
          response: {
            browser: this.deps.client.browser,
            extensionVersion: this.deps.client.extensionVersion,
            policyVersion: policy?.policyVersion ?? null,
            dnrRuleCount: (await this.deps.platform.dnr.getDynamicRules()).length,
            queuedEvents: (await this.state.queue()).length,
            lastError: health.lastError,
          },
        });
        return;
      }
      case 'REQUEST_POLICY':
      case 'CLIENT_HEALTH':
      case 'SECURITY_EVENT':
      case 'POLICY_STATUS':
        // Extension -> host messages; ignore if echoed back.
        return;
    }
  }

  /**
   * Handle a report from blocked.html. Only our own block page may report,
   * and the report is re-validated against the applied policy. Returns the
   * verified details the page may display, or null.
   */
  async onBlockPageReport(message: unknown, sender: MessageSenderLike, extensionId: string): Promise<BlockReportResult | null> {
    const pageUrl = `${this.deps.platform.extensionOrigin}${BLOCK_PAGE_PATH}`;
    if (sender.id !== extensionId || !sender.url?.startsWith(pageUrl)) return null;
    const m = message as Partial<BlockReportMessage> | null;
    if (!m || m.type !== 'BLOCK_PAGE_REPORT' || !Number.isInteger(m.ruleId) || (m.url !== null && typeof m.url !== 'string')) return null;
    const now = this.deps.platform.now();
    const event = buildUrlBlockedEvent(
      { ruleId: m.ruleId as number, url: m.url ? m.url.slice(0, 2048) : null },
      await this.state.getPolicy(),
      await this.clientInfo(),
      this.deps.platform.randomId(),
      now,
    );
    if (!event) return null;
    // Reloading the block page must not inflate the event count.
    if (this.deduper.shouldReport(`${event.ruleId}|${event.url ?? ''}`, now.getTime())) await this.send(event);
    return { domain: event.domain ?? null, category: event.threatCategory ?? null, ruleId: event.ruleId ?? null };
  }

  async emit(eventType: SecurityEventType, details: Record<string, unknown>, policyVersion?: number | null) {
    const c = await this.clientInfo();
    await this.send({
      eventId: this.deps.platform.randomId(),
      eventType,
      occurredAt: this.deps.platform.now().toISOString(),
      browserClientId: c.clientId,
      browser: c.browser,
      browserVersion: c.browserVersion,
      extensionVersion: c.extensionVersion,
      policyVersion: policyVersion ?? (await this.state.getPolicy())?.policyVersion ?? null,
      details,
    });
  }

  private async send(event: ReportedSecurityEvent) {
    if (!this.post({ type: 'SECURITY_EVENT', event })) await this.state.enqueue(event);
  }

  private async flushQueue() {
    const queued = await this.state.drain();
    for (let i = 0; i < queued.length; i++) {
      if (!this.post({ type: 'SECURITY_EVENT', event: queued[i]! })) {
        for (const e of queued.slice(i)) await this.state.enqueue(e);
        return;
      }
    }
  }

  async clientInfo(): Promise<ClientInfo> {
    return { ...this.deps.client, clientId: await this.state.clientId() };
  }

  async clientSnapshot() {
    const c = await this.clientInfo();
    const policy = await this.state.getPolicy();
    return {
      clientId: c.clientId,
      browser: c.browser,
      browserVersion: c.browserVersion,
      extensionVersion: c.extensionVersion,
      policyVersion: policy?.policyVersion ?? null,
      nativeConnected: this.connected,
      dnrRuleCount: (await this.deps.platform.dnr.getDynamicRules()).length,
    };
  }

  /** Popup status view. */
  async status() {
    const policy = await this.state.getPolicy();
    const health = await this.state.health();
    return {
      browser: this.deps.client.browser,
      extensionVersion: this.deps.client.extensionVersion,
      nativeConnected: this.connected,
      policyVersion: policy?.policyVersion ?? null,
      ruleCount: policy?.ruleCount ?? 0,
      appliedAt: policy?.appliedAt ?? null,
      lastPolicyStatus: health.lastPolicyStatus,
      lastError: health.lastError,
      queuedEvents: (await this.state.queue()).length,
    };
  }
}
