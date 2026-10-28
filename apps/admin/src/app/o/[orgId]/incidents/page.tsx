import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { buttonVariants } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { listIncidents } from '@/server/services/incidents';

export default async function IncidentsPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.incident.read');
  const incidents = await listIncidents(actor);
  return (
    <>
      <PageHeader
        title="Incidents"
        description="Incident response foundation: track investigations and issue endpoint commands."
        actions={
          actor.permissions.has('tenant.incident.create') ? (
            <Link className={buttonVariants()} href={`/o/${orgId}/incidents/new`}>
              Create Incident
            </Link>
          ) : null
        }
      />
      <Card>
        {incidents.length === 0 ? (
          <EmptyState title="No incidents" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Title</TH>
                <TH>Severity</TH>
                <TH>Status</TH>
                <TH className="text-right">Commands</TH>
                <TH>Created</TH>
              </TR>
            </THead>
            <TBody>
              {incidents.map((i) => (
                <TR key={i.id}>
                  <TD>
                    <Link
                      className="font-medium text-primary hover:underline"
                      href={`/o/${orgId}/incidents/${i.id}`}
                    >
                      {i.title}
                    </Link>
                  </TD>
                  <TD>
                    <StatusBadge status={i.severity} />
                  </TD>
                  <TD>
                    <StatusBadge status={i.status} />
                  </TD>
                  <TD className="text-right tabular-nums">{i.commandCount}</TD>
                  <TD className="text-xs">
                    {formatDateTime(i.createdAt)}
                    <div className="text-muted">{i.createdByEmail}</div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
