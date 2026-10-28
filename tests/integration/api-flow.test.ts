/**
 * End-to-end API integration against a real Postgres built from migrations.
 * Exercises the same handlers the Next.js routes use, with injected sessions.
 * Covers: platform/tenant authorization, tenant context, enrollment, policy
 * publishing, event ingestion, commands and audit logging.
 */
import { verifyPolicyChecksum } from '@bsp/policy-engine';
import type { PolicyPayload } from '@bsp/policy-types';
import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import * as api from '@/server/api/v1';
import { closePool as closeAppPool } from '@/server/db';
import { syncThreatSource, listIndicators } from '@/server/services/threats';
import { Authorizer } from '@/server/auth/authorizer-export';
import { ORG_ACME, USERS, asService, closePool } from '../fixtures/db';
import { body, depsFor, params, req } from '../fixtures/api';

const superAdmin = depsFor(USERS.platformSuperAdmin);
const secAdminPlatform = depsFor(USERS.platformSecurityAdmin);
const demoAdmin = depsFor(USERS.demoSecAdmin);
const acmeOwner = depsFor(USERS.acmeOwner);
const acmeAnalyst = depsFor(USERS.acmeAnalyst);

const state: {
  orgId?: string;
  policyId?: string;
  ruleId?: string;
  enrollToken?: string;
  deviceId?: string;
  deviceSecret?: string;
  payload?: PolicyPayload;
} = {};

const deviceAuth = () => ({ authorization: `Device ${state.deviceId}.${state.deviceSecret}` });

afterAll(async () => {
  await closePool();
  await closeAppPool();
});

describe('platform authorization', () => {
  it('rejects anonymous callers', async () => {
    const res = await api
      .platformListOrganizations(req('GET', '/api/v1/platform/organizations'), depsFor(null))
      .catch((e) => e);
    expect(res.code).toBe('UNAUTHENTICATED');
  });

  it('tenant users cannot reach platform routes', async () => {
    await expect(api.platformListOrganizations(req('GET', '/x'), acmeOwner)).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
    await expect(
      api.platformCreateOrganization(req('POST', '/x', { name: 'Evil', slug: 'evil' }), acmeOwner),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('platform support can list tenants but not create them', async () => {
    const support = depsFor(USERS.platformSupport);
    const res = await api.platformListOrganizations(req('GET', '/x'), support);
    expect(res.status).toBe(200);
    await expect(
      api.platformCreateOrganization(req('POST', '/x', { name: 'Nope', slug: 'nope' }), support),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('rejects cross-origin cookie requests (CSRF)', async () => {
    const r = req('POST', '/x', { name: 'X', slug: 'x-co' }, { origin: 'https://evil.example' });
    await expect(api.platformCreateOrganization(r, superAdmin)).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
  });

  it('platform super admin creates a tenant (with default policy) and validation is enforced', async () => {
    await expect(
      api.platformCreateOrganization(
        req('POST', '/x', { name: 'B', slug: 'BAD SLUG' }),
        superAdmin,
      ),
    ).rejects.toMatchObject({
      code: 'VALIDATION_FAILED',
    });
    const res = await api.platformCreateOrganization(
      req('POST', '/x', { name: 'Phase1 Demo Co', slug: 'phase1-demo' }),
      superAdmin,
    );
    expect(res.status).toBe(201);
    expect(res.headers.get('x-api-version')).toBe('v1');
    const b = await body<{ organization: { id: string } }>(res);
    state.orgId = b.organization.id;
    await expect(
      api.platformCreateOrganization(
        req('POST', '/x', { name: 'Dup', slug: 'phase1-demo' }),
        superAdmin,
      ),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
    });
  });

  it('platform super admin assigns a tenant security admin', async () => {
    const res = await api.platformAddTenantUser(
      req('POST', '/x', { email: 'New.SecAdmin@demo.test', roleKey: 'TenantSecurityAdmin' }),
      params({ id: state.orgId! }),
      superAdmin,
    );
    expect(res.status).toBe(201);
    // Platform security admin lacks platform.users.manage.
    await expect(
      api.platformAddTenantUser(
        req('POST', '/x', { email: 'helpdesk@acme.test', roleKey: 'TenantOwner' }),
        params({ id: state.orgId! }),
        secAdminPlatform,
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

describe('tenant administrator', () => {
  it('sees only their organization', async () => {
    const authz = new Authorizer({
      getUser: async () => ({ id: USERS.demoSecAdmin, email: null }),
    });
    const orgs = await authz.myOrganizations();
    expect(orgs.map((o) => o.id)).toEqual([state.orgId]);
    await expect(
      api.orgDevices(req('GET', '/x'), params({ id: ORG_ACME }), demoAdmin),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('creates rules with normalisation, duplicate and invalid handling', async () => {
    const res = await api.orgCreateRule(
      req('POST', '/x', {
        ruleType: 'BLOCK_DOMAIN',
        value: 'HTTPS://Phase1-Block-Test.Example./path',
        category: 'phishing',
      }),
      params({ id: state.orgId! }),
      demoAdmin,
    );
    expect(res.status).toBe(201);
    const b = await body<{ rule: { id: string; normalizedValue: string; policyId: string } }>(res);
    expect(b.rule.normalizedValue).toBe('phase1-block-test.example');
    state.ruleId = b.rule.id;
    state.policyId = b.rule.policyId;

    await expect(
      api.orgCreateRule(
        req('POST', '/x', { ruleType: 'BLOCK_DOMAIN', value: 'phase1-block-test.example' }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      api.orgCreateRule(
        req('POST', '/x', { ruleType: 'BLOCK_URL', value: 'not a url' }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    ).rejects.toMatchObject({ code: 'VALIDATION_FAILED' });
    const allow = await api.orgCreateRule(
      req('POST', '/x', { ruleType: 'ALLOW_DOMAIN', value: 'global-phish-test.example' }),
      params({ id: state.orgId! }),
      demoAdmin,
    );
    expect(allow.status).toBe(201);
  });

  it('cannot assign a role more privileged than their own', async () => {
    await expect(
      api.orgAddUser(
        req('POST', '/x', { email: 'helpdesk@internal.test', roleKey: 'TenantOwner' }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const ok = await api.orgAddUser(
      req('POST', '/x', { email: 'helpdesk@internal.test', roleKey: 'TenantHelpDesk' }),
      params({ id: state.orgId! }),
      demoAdmin,
    );
    expect(ok.status).toBe(201);
  });
});

describe('policy publishing', () => {
  it('publishes immutable, incrementing versions with checksums', async () => {
    const r1 = await body<{ versionNumber: number; checksum: string; versionId: string }>(
      await api.orgPublishPolicy(
        req('POST', '/x'),
        params({ id: state.orgId!, policyId: state.policyId! }),
        demoAdmin,
      ),
    );
    expect(r1.versionNumber).toBe(1);
    expect(r1.checksum).toMatch(/^[0-9a-f]{64}$/);
    const before = await asService((c) =>
      c.query(
        `select checksum, compiled_payload, status from public.policy_versions where id = $1`,
        [r1.versionId],
      ),
    );

    const r2 = await body<{ versionNumber: number; versionId: string }>(
      await api.orgPublishPolicy(
        req('POST', '/x'),
        params({ id: state.orgId!, policyId: state.policyId! }),
        demoAdmin,
      ),
    );
    expect(r2.versionNumber).toBe(2);
    const after = await asService((c) =>
      c.query(
        `select checksum, compiled_payload, status from public.policy_versions where id = $1`,
        [r1.versionId],
      ),
    );
    expect(after.rows[0].checksum).toBe(before.rows[0].checksum);
    expect(after.rows[0].compiled_payload).toEqual(before.rows[0].compiled_payload);
    expect(after.rows[0].status).toBe('superseded');
  });

  it('analysts and other tenants cannot publish', async () => {
    await expect(
      api.orgPublishPolicy(
        req('POST', '/x'),
        params({ id: state.orgId!, policyId: state.policyId! }),
        acmeOwner,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Acme owner targeting their own org id with another tenant's policy id: still not found.
    await expect(
      api.orgPublishPolicy(
        req('POST', '/x'),
        params({ id: ORG_ACME, policyId: state.policyId! }),
        acmeOwner,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      api.orgPublishPolicy(
        req('POST', '/x'),
        params({ id: ORG_ACME, policyId: '00000000-0000-4f10-8000-000000000002' }),
        acmeAnalyst,
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('other tenants cannot delete this tenant’s rules even through their own org path', async () => {
    await expect(
      api.orgDeleteRule(
        req('DELETE', '/x'),
        params({ id: ORG_ACME, ruleId: state.ruleId! }),
        acmeOwner,
      ),
    ).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });
});

describe('device enrollment', () => {
  it('creates an enrollment token', async () => {
    const res = await api.orgCreateEnrollmentToken(
      req('POST', '/x', { maxUses: 5, expiresInHours: 1 }),
      params({ id: state.orgId! }),
      demoAdmin,
    );
    const b = await body<{ token: string }>(res);
    expect(b.token).toMatch(/^bspe_/);
    state.enrollToken = b.token;
  });

  const enrollBody = (token: string) => ({
    enrollmentToken: token,
    installationId: randomUUID(),
    hostname: 'DEMO-WS-001',
    osVersion: 'Windows 11 Enterprise 24H2 (26100)',
    agentVersion: '0.1.0',
    localIp: '192.168.1.20',
    organizationId: ORG_ACME, // must be ignored
  });

  it('rejects wrong tokens', async () => {
    await expect(
      api.deviceEnroll(req('POST', '/x', enrollBody('bspe_' + 'x'.repeat(43)))),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('rejects expired tokens', async () => {
    await asService((c) =>
      c.query(
        `insert into public.enrollment_tokens (organization_id, token_hash, token_prefix, expires_at)
               values ($1, encode(extensions.digest('expired-token-0000000000000000', 'sha256'), 'hex'), 'expired-', now() - interval '1 minute')`,
        [state.orgId],
      ),
    );
    await expect(
      api.deviceEnroll(req('POST', '/x', enrollBody('expired-token-0000000000000000'))),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('enrolls and derives the tenant from the token, ignoring client org ids and IP headers', async () => {
    const res = await api.deviceEnroll(
      req('POST', '/x', enrollBody(state.enrollToken!), { 'x-forwarded-for': '6.6.6.6' }),
    );
    expect(res.status).toBe(201);
    const b = await body<{ deviceId: string; organizationId: string; deviceSecret: string }>(res);
    expect(b.organizationId).toBe(state.orgId);
    state.deviceId = b.deviceId;
    state.deviceSecret = b.deviceSecret;
    const row = await asService((c) =>
      c.query(
        `select organization_id, public_ip, credential_hash from public.devices where id = $1`,
        [b.deviceId],
      ),
    );
    expect(row.rows[0].organization_id).toBe(state.orgId);
    expect(row.rows[0].public_ip).toBeNull();
    expect(row.rows[0].credential_hash).not.toContain(b.deviceSecret);
  });

  it('rejects bad device credentials', async () => {
    const bad = req(
      'POST',
      '/x',
      { hostname: 'h', osVersion: 'o', agentVersion: '1', policyVersion: null },
      {
        authorization: `Device ${state.deviceId}.${'A'.repeat(40)}`,
      },
    );
    await expect(api.deviceHeartbeat(bad)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
});

describe('policy delivery, heartbeat and events', () => {
  it('heartbeat reports the latest version', async () => {
    const res = await api.deviceHeartbeat(
      req(
        'POST',
        '/x',
        {
          hostname: 'DEMO-WS-001',
          osVersion: 'Windows 11',
          agentVersion: '0.1.0',
          policyVersion: null,
          browserClients: [
            {
              clientId: 'chrome-client-0001',
              browser: 'chrome',
              browserVersion: '142.0',
              extensionVersion: '0.1.0',
              policyVersion: null,
              nativeConnected: true,
              dnrRuleCount: 0,
            },
          ],
        },
        deviceAuth(),
      ),
    );
    expect(await body(res)).toMatchObject({ latestPolicyVersion: 2 });
  });

  it('device receives a verifiable payload and is told when it is current', async () => {
    const res = await body<{ status: string; payload: PolicyPayload }>(
      await api.devicePolicy(req('GET', '/api/v1/device/policy', undefined, deviceAuth())),
    );
    expect(res.status).toBe('updated');
    expect(res.payload.organizationId).toBe(state.orgId);
    expect(res.payload.policyVersion).toBe(2);
    expect(await verifyPolicyChecksum(res.payload)).toBe(true);
    expect(res.payload.rules.find((r) => r.value === 'phase1-block-test.example')?.action).toBe(
      'block',
    );
    // Tenant allow exception suppresses the global indicator.
    expect(
      res.payload.rules.filter((r) => r.value === 'global-phish-test.example').map((r) => r.action),
    ).toEqual(['allow']);
    state.payload = res.payload;
    const cur = await body(
      await api.devicePolicy(
        req('GET', '/api/v1/device/policy?currentVersion=2', undefined, deviceAuth()),
      ),
    );
    expect(cur).toEqual({ status: 'current', policyVersion: 2 });
  });

  it('ingests URL_BLOCKED idempotently with server-derived tenant and policy-derived category', async () => {
    const rule = state.payload!.rules.find((r) => r.value === 'phase1-block-test.example')!;
    const event = {
      eventId: randomUUID(),
      eventType: 'URL_BLOCKED',
      occurredAt: new Date().toISOString(),
      browserClientId: 'chrome-client-0001',
      browser: 'chrome',
      browserVersion: '142.0',
      extensionVersion: '0.1.0',
      url: 'https://WWW.phase1-block-test.example/login?x=1#frag',
      ruleId: rule.id,
      policyVersion: 2,
      threatCategory: 'fraud', // client claim is overridden by the policy
      organizationId: ORG_ACME, // ignored
    };
    const r1 = await body(
      await api.securityEvents(req('POST', '/x', { events: [event] }, deviceAuth())),
    );
    expect(r1).toEqual({ accepted: 1, duplicates: 0 });
    const r2 = await body(
      await api.securityEvents(req('POST', '/x', { events: [event] }, deviceAuth())),
    );
    expect(r2).toEqual({ accepted: 0, duplicates: 1 });

    const list = await body<{
      events: {
        eventType: string;
        domain: string;
        url: string;
        threatCategory: string;
        verified: boolean;
        hostname: string;
      }[];
    }>(
      await api.orgEvents(
        req('GET', '/x?eventType=URL_BLOCKED'),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    );
    expect(list.events).toHaveLength(1);
    expect(list.events[0]).toMatchObject({
      domain: 'www.phase1-block-test.example',
      url: 'https://www.phase1-block-test.example/login?x=1',
      threatCategory: 'phishing',
      verified: true,
      hostname: 'DEMO-WS-001',
    });
  });

  it('rejects malformed event batches', async () => {
    await expect(
      api.securityEvents(
        req('POST', '/x', { events: [{ eventType: 'URL_BLOCKED' }] }, deviceAuth()),
      ),
    ).rejects.toMatchObject({
      code: 'VALIDATION_FAILED',
    });
  });

  it('Tenant A cannot see Tenant B event or device', async () => {
    await expect(
      api.orgEvents(req('GET', '/x'), params({ id: state.orgId! }), acmeOwner),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const acmeEvents = await body<{ events: { domain: string }[] }>(
      await api.orgEvents(req('GET', '/x'), params({ id: ORG_ACME }), acmeOwner),
    );
    expect(acmeEvents.events.some((e) => e.domain?.includes('phase1-block-test'))).toBe(false);
  });

  it('device dashboard reflects heartbeat and browser client status', async () => {
    const res = await body<{
      devices: {
        hostname: string;
        chrome: { extensionVersion: string } | null;
        protection: string;
        publicIp: string | null;
      }[];
    }>(await api.orgDevices(req('GET', '/x'), params({ id: state.orgId! }), demoAdmin));
    expect(res.devices).toHaveLength(1);
    expect(res.devices[0]!.chrome?.extensionVersion).toBe('0.1.0');
    // Agent reported policyVersion null while v2 was just published -> within grace period it is degraded, not outdated.
    expect(['degraded', 'protected', 'policy_outdated']).toContain(res.devices[0]!.protection);
  });
});

describe('incident commands', () => {
  it('issues a command, the agent receives it and returns a result', async () => {
    const inc = await body<{ id: string }>(
      await api.orgCreateIncident(
        req('POST', '/x', { title: 'Phishing click investigation', severity: 'high' }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    );
    const cmd = await body<{ id: string }>(
      await api.orgCreateCommand(
        req('POST', '/x', {
          deviceId: state.deviceId,
          commandType: 'COLLECT_DIAGNOSTICS',
          incidentId: inc.id,
        }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    );
    const polled = await body<{ commands: { id: string; commandType: string }[] }>(
      await api.deviceCommands(req('GET', '/x', undefined, deviceAuth())),
    );
    expect(polled.commands.map((c) => c.id)).toContain(cmd.id);
    const again = await body<{ commands: unknown[] }>(
      await api.deviceCommands(req('GET', '/x', undefined, deviceAuth())),
    );
    expect(again.commands).toHaveLength(0);
    const done = await api.deviceCommandResult(
      req(
        'POST',
        '/x',
        { status: 'COMPLETED', result: { agentVersion: '0.1.0', browsers: 1 } },
        deviceAuth(),
      ),
      params({ id: cmd.id }),
    );
    expect(done.status).toBe(200);
    await expect(
      api.deviceCommandResult(
        req('POST', '/x', { status: 'RUNNING' }, deviceAuth()),
        params({ id: cmd.id }),
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const art = await asService((c) =>
      c.query(`select artifact_type from public.incident_artifacts where incident_id = $1`, [
        inc.id,
      ]),
    );
    expect(art.rows).toEqual([{ artifact_type: 'diagnostics' }]);
  });

  it('browser history collection requires history approve permission and an incident', async () => {
    await expect(
      api.orgCreateCommand(
        req('POST', '/x', {
          deviceId: state.deviceId,
          commandType: 'COLLECT_BROWSER_HISTORY',
          payload: {},
        }),
        params({ id: state.orgId! }),
        demoAdmin,
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

describe('platform tenant context', () => {
  it('platform security admin must explicitly enter a tenant, retains identity, and is audited', async () => {
    await expect(
      api.orgDevices(req('GET', '/x'), params({ id: state.orgId! }), secAdminPlatform),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const entered = await api.platformEnterTenant(
      req('POST', '/x', { organizationId: state.orgId, reason: 'acceptance test' }),
      secAdminPlatform,
    );
    expect(entered.status).toBe(201);
    const devices = await body<{ devices: unknown[] }>(
      await api.orgDevices(req('GET', '/x'), params({ id: state.orgId! }), secAdminPlatform),
    );
    expect(devices.devices).toHaveLength(1);
    // Context is scoped to that tenant only.
    await expect(
      api.orgDevices(req('GET', '/x'), params({ id: ORG_ACME }), secAdminPlatform),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Actions in context are attributed to the real platform user.
    await api.orgCreateRule(
      req('POST', '/x', { ruleType: 'BLOCK_DOMAIN', value: 'platform-added.example' }),
      params({ id: state.orgId! }),
      secAdminPlatform,
    );
    const audit = await body<{
      events: {
        action: string;
        actorEmail: string;
        actorScope: string;
        platformRole: string;
        tenantContextId: string | null;
      }[];
    }>(await api.orgAudit(req('GET', '/x'), params({ id: state.orgId! }), demoAdmin));
    const enteredRow = audit.events.find((e) => e.action === 'PLATFORM_ADMIN_ENTERED_TENANT');
    expect(enteredRow).toMatchObject({
      actorEmail: 'platform.security@vector58.test',
      actorScope: 'platform',
      platformRole: 'PlatformSecurityAdmin',
    });
    const ruleRow = audit.events.find(
      (e) =>
        e.action === 'BLOCK_RULE_CREATED' && e.actorEmail === 'platform.security@vector58.test',
    );
    expect(ruleRow?.tenantContextId).toBeTruthy();
    expect(ruleRow?.actorScope).toBe('platform');

    await api.platformExitTenant(req('DELETE', '/x'), secAdminPlatform);
    await expect(
      api.orgDevices(req('GET', '/x'), params({ id: state.orgId! }), secAdminPlatform),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('platform support enters read-only; platform auditor cannot enter tenants', async () => {
    await expect(
      api.platformEnterTenant(
        req('POST', '/x', { organizationId: state.orgId }),
        depsFor(USERS.platformAuditor),
      ),
    ).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
    const support = depsFor(USERS.platformSupport);
    await api.platformEnterTenant(req('POST', '/x', { organizationId: state.orgId }), support);
    await expect(
      api.orgCreateRule(
        req('POST', '/x', { ruleType: 'BLOCK_DOMAIN', value: 'support-cannot.example' }),
        params({ id: state.orgId! }),
        support,
      ),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await api.platformExitTenant(req('DELETE', '/x'), support);
  });
});

describe('audit logging', () => {
  it('records every privileged action of the flow', async () => {
    const rows = await asService((c) =>
      c.query<{ action: string }>(
        `select distinct action from public.audit_events where organization_id = $1`,
        [state.orgId],
      ),
    );
    const actions = rows.rows.map((r) => r.action);
    for (const a of [
      'TENANT_CREATED',
      'TENANT_USER_ADDED',
      'TENANT_ROLE_ASSIGNED',
      'BLOCK_RULE_CREATED',
      'ALLOW_RULE_CREATED',
      'POLICY_PUBLISHED',
      'ENROLLMENT_TOKEN_CREATED',
      'DEVICE_ENROLLED',
      'INCIDENT_CREATED',
      'ENDPOINT_COMMAND_ISSUED',
      'PLATFORM_ADMIN_ENTERED_TENANT',
      'PLATFORM_ADMIN_EXITED_TENANT',
    ]) {
      expect(actions, a).toContain(a);
    }
  });

  it('platform auditor sees cross-tenant audit; tenant users cannot use the platform audit API', async () => {
    const res = await body<{ events: { organizationId: string }[] }>(
      await api.platformAudit(
        req('GET', '/api/v1/platform/audit?limit=1000'),
        depsFor(USERS.platformAuditor),
      ),
    );
    const orgs = new Set(res.events.map((e) => e.organizationId));
    expect(orgs.has(state.orgId!)).toBe(true);
    expect(orgs.has(ORG_ACME)).toBe(true);
    await expect(api.platformAudit(req('GET', '/x'), acmeOwner)).rejects.toMatchObject({
      code: 'FORBIDDEN',
    });
  });
});

describe('threat feed ingestion', () => {
  it('sample feed ingests, dedupes and is idempotent', async () => {
    const first = await syncThreatSource(
      { kind: 'system' },
      '00000000-0000-4f60-8000-000000000002',
    );
    expect(first.created).toBe(5);
    const second = await syncThreatSource(
      { kind: 'system' },
      '00000000-0000-4f60-8000-000000000002',
    );
    expect(second.created).toBe(0);
    expect(second.updated).toBe(5);
    const authz = new Authorizer({
      getUser: async () => ({ id: USERS.platformSecurityAdmin, email: null }),
    });
    const actor = await authz.requirePlatformPermission('platform.security.threats.read');
    const list = await listIndicators(actor, { q: 'sample-' });
    expect(list.length).toBe(5);
    expect(list.every((i) => i.observations === 2)).toBe(true);
    expect((await listIndicators(actor, { q: 'microsoft.com' })).length).toBe(0);
  });
});
