import { describe, expect, it } from 'vitest';
import {
  AgentHeartbeatSchema,
  CollectBrowserHistoryPayloadSchema,
  CreateRuleRequestSchema,
  EnrollmentRequestSchema,
  NativeMessageSchema,
  PolicyPayloadSchema,
  SecurityEventBatchSchema,
} from './index';

const ORG = '11111111-1111-4111-8111-111111111111';
const payload = {
  schemaVersion: 1,
  policyVersion: 42,
  organizationId: ORG,
  generatedAt: '2026-10-28T12:00:00.000Z',
  checksum: 'a'.repeat(64),
  rules: [
    {
      id: 10001,
      type: 'domain',
      value: 'bad-domain.example',
      action: 'block',
      category: 'phishing',
      priority: 100,
      source: 'tenant',
    },
  ],
};

describe('PolicyPayloadSchema', () => {
  it('accepts the documented example', () => {
    expect(PolicyPayloadSchema.safeParse(payload).success).toBe(true);
  });
  it('rejects unknown schema versions, bad checksums and duplicate ids', () => {
    expect(PolicyPayloadSchema.safeParse({ ...payload, schemaVersion: 2 }).success).toBe(false);
    expect(PolicyPayloadSchema.safeParse({ ...payload, checksum: 'xyz' }).success).toBe(false);
    expect(
      PolicyPayloadSchema.safeParse({ ...payload, rules: [payload.rules[0], payload.rules[0]] })
        .success,
    ).toBe(false);
  });
  it('rejects rule ids outside the DNR-safe range', () => {
    const bad = { ...payload, rules: [{ ...payload.rules[0], id: 2 ** 30 }] };
    expect(PolicyPayloadSchema.safeParse(bad).success).toBe(false);
  });
});

describe('NativeMessageSchema', () => {
  it('parses POLICY_UPDATE', () => {
    const r = NativeMessageSchema.safeParse({ type: 'POLICY_UPDATE', policyVersion: 42, payload });
    expect(r.success).toBe(true);
  });
  it('rejects unknown message types', () => {
    expect(NativeMessageSchema.safeParse({ type: 'RUN_SHELL', cmd: 'calc.exe' }).success).toBe(
      false,
    );
  });
});

describe('device API schemas', () => {
  it('enrollment ignores client-supplied organization ids', () => {
    const r = EnrollmentRequestSchema.parse({
      enrollmentToken: 'x'.repeat(32),
      installationId: ORG,
      hostname: 'WIN-01',
      osVersion: 'Windows 11',
      agentVersion: '0.1.0',
      organizationId: '22222222-2222-4222-8222-222222222222',
    } as never);
    expect('organizationId' in r).toBe(false);
  });
  it('heartbeat defaults browser clients', () => {
    const r = AgentHeartbeatSchema.parse({
      hostname: 'h',
      osVersion: 'o',
      agentVersion: '1',
      policyVersion: null,
    });
    expect(r.browserClients).toEqual([]);
  });
  it('event batch caps size', () => {
    expect(SecurityEventBatchSchema.safeParse({ events: [] }).success).toBe(false);
  });
  it('rule requests validate rule types', () => {
    expect(
      CreateRuleRequestSchema.safeParse({ ruleType: 'BLOCK_EVERYTHING', value: 'x' }).success,
    ).toBe(false);
    expect(
      CreateRuleRequestSchema.parse({ ruleType: 'BLOCK_DOMAIN', value: 'x.example' }).category,
    ).toBe('custom');
  });
  it('history collection must be bounded', () => {
    const base = { incidentId: ORG, approvedBy: ORG, startTime: '2026-10-01T00:00:00Z' };
    expect(
      CollectBrowserHistoryPayloadSchema.safeParse({ ...base, endTime: '2026-10-02T00:00:00Z' })
        .success,
    ).toBe(true);
    expect(
      CollectBrowserHistoryPayloadSchema.safeParse({ ...base, endTime: '2026-10-30T00:00:00Z' })
        .success,
    ).toBe(false);
    expect(
      CollectBrowserHistoryPayloadSchema.safeParse({ ...base, endTime: '2026-09-30T00:00:00Z' })
        .success,
    ).toBe(false);
  });
});
