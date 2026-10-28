import Link from 'next/link';
import { removeRuleAction } from '@/app/actions/tenant';
import { ActionButton } from '@/components/action-button';
import { EmptyState, PageHeader } from '@/components/page';
import { RuleForm } from '@/components/rule-form';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { getPolicyDetail, listPolicies } from '@/server/services/policies';

export default async function AllowListPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.policy.read');
  const def = (await listPolicies(actor)).find((p) => p.isDefault);
  if (!def) return <EmptyState title="No default policy" />;
  const { rules } = await getPolicyDetail(actor, def.id);
  const allows = rules.filter((r) => r.ruleType.startsWith('ALLOW'));
  const canWrite = actor.permissions.has('tenant.policy.write');
  return (
    <>
      <PageHeader
        title="Allow List"
        description="Explicit organization allow exceptions. They override organization blocks and global threat intelligence."
      />
      <div className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Allowed destinations ({allows.length})</CardTitle>
            <Link href={`/o/${orgId}/policies/${def.id}`} className="text-xs text-primary">
              Publish from policy page
            </Link>
          </CardHeader>
          {allows.length === 0 ? (
            <EmptyState title="No allow exceptions" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Type</TH>
                  <TH>Value</TH>
                  <TH>Reason</TH>
                  <TH>Created</TH>
                  <TH />
                </TR>
              </THead>
              <TBody>
                {allows.map((r) => (
                  <TR key={r.id}>
                    <TD>
                      <Badge tone="success">{r.ruleType}</Badge>
                    </TD>
                    <TD className="font-mono text-xs">{r.normalizedValue}</TD>
                    <TD className="text-xs">{r.reason ?? '—'}</TD>
                    <TD className="text-xs">{formatDateTime(r.createdAt)}</TD>
                    <TD>
                      {canWrite ? (
                        <ActionButton
                          label="Delete"
                          variant="ghost"
                          confirm="Remove this allow exception?"
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
        {canWrite ? (
          <Card>
            <CardHeader>
              <CardTitle>Add allow entry</CardTitle>
            </CardHeader>
            <CardContent>
              <RuleForm orgId={orgId} policyId={def.id} mode="allow" />
            </CardContent>
          </Card>
        ) : null}
      </div>
    </>
  );
}
