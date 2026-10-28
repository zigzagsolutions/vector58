import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { StatusBadge } from '@/components/status';
import { buttonVariants } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { platformPage } from '@/server/page-guards';
import { listOrganizations } from '@/server/services/organizations';

export default async function CustomersPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const actor = await platformPage('platform.tenants.read');
  const sp = await searchParams;
  const q = sp.q?.toLowerCase();
  const all = await listOrganizations(actor);
  const rows = all.filter((o) => (!q || o.name.toLowerCase().includes(q) || o.slug.includes(q)) && (!sp.status || o.status === sp.status));
  return (
    <>
      <PageHeader
        title="Customers"
        description="Every tenant, including the internal organization, is a regular customer tenant."
        actions={actor.permissions.has('platform.tenants.manage') ? <Link className={buttonVariants()} href="/platform/customers/new">Create Customer</Link> : null}
      />
      <Card>
        <SearchForm
          values={sp}
          fields={[
            { name: 'q', label: 'Search', placeholder: 'Name or slug' },
            { name: 'status', label: 'Status', type: 'select', options: [{ value: 'active', label: 'Active' }, { value: 'disabled', label: 'Disabled' }] },
          ]}
        />
        {rows.length === 0 ? (
          <EmptyState title="No customers match" description="Adjust the filters or create a customer tenant." />
        ) : (
          <Table>
            <THead><TR><TH>Name</TH><TH>Status</TH><TH className="text-right">Devices</TH><TH className="text-right">Active users</TH><TH className="text-right">Latest policy</TH><TH>Last activity</TH></TR></THead>
            <TBody>
              {rows.map((o) => (
                <TR key={o.id}>
                  <TD><Link className="font-medium text-primary hover:underline" href={`/platform/customers/${o.id}`}>{o.name}</Link><div className="text-xs text-muted">{o.slug}</div></TD>
                  <TD><StatusBadge status={o.status} /></TD>
                  <TD className="text-right tabular-nums">{o.deviceCount}</TD>
                  <TD className="text-right tabular-nums">{o.activeUsers}</TD>
                  <TD className="text-right tabular-nums">{o.latestPolicyVersion ? `v${o.latestPolicyVersion}` : '—'}</TD>
                  <TD>{relativeTime(o.lastActivity)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
