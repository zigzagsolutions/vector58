import type { CompiledRule, ReportedSecurityEvent } from '@bsp/policy-types';
import type { ExtensionPlatform } from './platform';

export interface AppliedPolicyMeta {
  readonly policyVersion: number;
  readonly checksum: string;
  readonly organizationId: string;
  readonly appliedAt: string;
  readonly ruleCount: number;
  readonly dnrRuleCount: number;
  /** Rule index used to validate and enrich block-page reports. */
  readonly rules: Pick<CompiledRule, 'id' | 'type' | 'value' | 'action' | 'category'>[];
}

export interface HealthState {
  nativeConnected: boolean;
  lastError: string | null;
  lastPolicyStatus: 'applied' | 'failed' | 'unchanged' | null;
}

const KEYS = {
  policy: 'bsp.policy',
  clientId: 'bsp.clientId',
  queue: 'bsp.eventQueue',
  health: 'bsp.health',
} as const;

export const MAX_QUEUED_EVENTS = 500;

export class ExtensionState {
  /** Serializes read-modify-write cycles on storage (events arrive concurrently). */
  private lock: Promise<unknown> = Promise.resolve();
  constructor(private readonly p: ExtensionPlatform) {}

  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.lock.then(fn, fn);
    this.lock = run.catch(() => undefined);
    return run;
  }

  getPolicy() {
    return this.p.storage.get<AppliedPolicyMeta>(KEYS.policy);
  }
  setPolicy(meta: AppliedPolicyMeta) {
    return this.p.storage.set(KEYS.policy, meta);
  }

  async clientId(): Promise<string> {
    const existing = await this.p.storage.get<string>(KEYS.clientId);
    if (existing) return existing;
    const id = this.p.randomId();
    await this.p.storage.set(KEYS.clientId, id);
    return id;
  }

  async health(): Promise<HealthState> {
    return (
      (await this.p.storage.get<HealthState>(KEYS.health)) ?? {
        nativeConnected: false,
        lastError: null,
        lastPolicyStatus: null,
      }
    );
  }
  updateHealth(patch: Partial<HealthState>) {
    return this.exclusive(async () =>
      this.p.storage.set(KEYS.health, { ...(await this.health()), ...patch }),
    );
  }

  async queue(): Promise<ReportedSecurityEvent[]> {
    return (await this.p.storage.get<ReportedSecurityEvent[]>(KEYS.queue)) ?? [];
  }
  /** Bounded FIFO so a long disconnect cannot exhaust extension storage. */
  enqueue(e: ReportedSecurityEvent) {
    return this.exclusive(async () => {
      const q = await this.queue();
      q.push(e);
      await this.p.storage.set(KEYS.queue, q.slice(-MAX_QUEUED_EVENTS));
    });
  }
  drain(): Promise<ReportedSecurityEvent[]> {
    return this.exclusive(async () => {
      const q = await this.queue();
      await this.p.storage.set(KEYS.queue, []);
      return q;
    });
  }
}
