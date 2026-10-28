import Link from 'next/link';
import { publishPolicyAction, removeRuleAction } from '@/app/actions/tenant';
import { ActionButton } from '@/components/action-button';
import { EmptyState, Mono, PageHeader } from '@/components/page';
import { CategoryBadge, StatusBadge } from '@/components/status';
import { Badge } from '@/components/ui/badge';
import { buttonVariants } from '@/components/ui/button';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { getPolicyDetail } from '@/server/services/policies';

export default async function PolicyDetailPage({
  params,
}: {
  params: Promise<{ orgId: string; policyId: string }>;
}) {
  const { orgId, policyId } = await params;
  const actor = await tenantPage(orgId, 'tenant.policy.read');
  const { policy, rules, versions } = await getPolicyDetail(actor, policyId);
  const canWrite = actor.permissions.has('tenant.policy.write');
  const canPublish = actor.permissions.has('tenant.policy.publish');
  return (
    <>
      <PageHeader
        title={policy.name}
        description={`${policy.includeGlobalThreats ? `Includes global threat intelligence (confidence ≥ ${policy.minGlobalConfidence}).` : 'Global intelligence excluded.'} Current version: ${policy.currentVersion ? `v${policy.currentVersion}` : 'unpublished'}.`}
        actions={
          <>
            {canWrite ? (
              <Link
                className={buttonVariants({ variant: 'outline' })}
                href={`/o/${orgId}/policies/${policyId}/add-rule`}
              >
                Add Block Rule
              </Link>
            ) : null}
            {canPublish ? (
              <ActionButton
                size="md"
                variant="default"
                label="Publish Policy"
                confirm="Compile and publish a new immutable policy version to all endpoints?"
                action={publishPolicyAction.bind(null, orgId, policyId)}
              />
            ) : null}
          </>
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>Rules ({rules.length})</CardTitle>
          <span className="text-xs text-muted">
            Precedence: allow exception › organization block › global block › default allow
          </span>
        </CardHeader>
        {rules.length === 0 ? (
          <EmptyState
            title="No rules yet"
            description="Add a block rule, then publish the policy."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Value</TH>
                <TH>Category</TH>
                <TH className="text-right">Priority</TH>
                <TH>Reason</TH>
                <TH>Created</TH>
                <TH />
              </TR>
            </THead>
            <TBody>
              {rules.map((r) => (
                <TR key={r.id}>
                  <TD>
                    <Badge tone={r.ruleType.startsWith('ALLOW') ? 'success' : 'danger'}>
                      {r.ruleType}
                    </Badge>
                  </TD>
                  <TD className="font-mono text-xs">
                    {r.normalizedValue}
                    {r.expiresAt ? (
                      <div className="text-muted">expires {formatDateTime(r.expiresAt)}</div>
                    ) : null}
                  </TD>
                  <TD>
                    <CategoryBadge category={r.category} />
                  </TD>
                  <TD className="text-right tabular-nums">{r.priority}</TD>
                  <TD className="max-w-56 truncate text-xs" title={r.reason ?? ''}>
                    {r.reason ?? '—'}
                  </TD>
                  <TD className="text-xs">
                    {formatDateTime(r.createdAt)}
                    <div className="text-muted">{r.createdByEmail}</div>
                  </TD>
                  <TD>
                    {canWrite ? (
                      <ActionButton
                        label="Delete"
                        variant="ghost"
                        confirm={`Remove ${r.normalizedValue}? Takes effect at next publish.`}
                        action={removeRuleAction.bind(null, orgId, r.id)}
                      />
                    ) : null}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>Published versions</CardTitle>
          <span className="text-xs text-muted">Immutable. Older versions are never modified.</span>
        </CardHeader>
        {versions.length === 0 ? (
          <EmptyState title="Never published" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Version</TH>
                <TH>Status</TH>
                <TH className="text-right">Rules</TH>
                <TH>Checksum (SHA-256)</TH>
                <TH>Published</TH>
                <TH>By</TH>
              </TR>
            </THead>
            <TBody>
              {versions.map((v) => (
                <TR key={v.id}>
                  <TD className="font-semibold">v{v.versionNumber}</TD>
                  <TD>
                    <StatusBadge status={v.status} />
                  </TD>
                  <TD className="text-right tabular-nums">{v.ruleCount}</TD>
                  <TD>
                    <Mono>{v.checksum.slice(0, 20)}…</Mono>
                  </TD>
                  <TD>{formatDateTime(v.publishedAt)}</TD>
                  <TD>{v.createdByEmail ?? '—'}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
