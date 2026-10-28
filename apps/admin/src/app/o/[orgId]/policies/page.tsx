import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { listPolicies } from '@/server/services/policies';

export default async function PoliciesPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.policy.read');
  const policies = await listPolicies(actor);
  return (
    <>
      <PageHeader title="Policies" description="Block and allow rules compiled into immutable, versioned policy for endpoints. Phase 1 delivers the default policy to every device." />
      <Card>
        {policies.length === 0 ? <EmptyState title="No policies" /> : (
          <Table>
            <THead><TR><TH>Name</TH><TH className="text-right">Rules</TH><TH>Global intel</TH><TH>Published version</TH><TH>Updated</TH></TR></THead>
            <TBody>
              {policies.map((p) => (
                <TR key={p.id}>
                  <TD><Link className="font-medium text-primary hover:underline" href={`/o/${orgId}/policies/${p.id}`}>{p.name}</Link> {p.isDefault ? <Badge tone="info">default</Badge> : null}<div className="text-xs text-muted">{p.description}</div></TD>
                  <TD className="text-right tabular-nums">{p.ruleCount}</TD>
                  <TD>{p.includeGlobalThreats ? 'Included' : 'Excluded'}</TD>
                  <TD>{p.currentVersion ? `v${p.currentVersion}` : <Badge tone="warning">unpublished</Badge>}</TD>
                  <TD>{relativeTime(p.updatedAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
