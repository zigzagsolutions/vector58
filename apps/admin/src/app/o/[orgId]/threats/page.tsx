import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { CategoryBadge } from '@/components/status';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { blockedThreatSummary } from '@/server/services/events';

export default async function TenantThreatsPage({
  params,
}: {
  params: Promise<{ orgId: string }>;
}) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.events.read');
  const rows = await blockedThreatSummary(actor);
  return (
    <>
      <PageHeader
        title="Threats"
        description="Destinations blocked on your endpoints in the last 30 days."
      />
      <Card>
        {rows.length === 0 ? (
          <EmptyState title="No blocked threats in the last 30 days" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Domain</TH>
                <TH>Category</TH>
                <TH className="text-right">Blocks</TH>
                <TH className="text-right">Devices</TH>
                <TH>Last seen</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={`${r.domain}-${r.category}`}>
                  <TD className="font-mono text-xs">
                    <Link
                      className="text-primary hover:underline"
                      href={`/o/${orgId}/events?domain=${encodeURIComponent(r.domain ?? '')}`}
                    >
                      {r.domain ?? '—'}
                    </Link>
                  </TD>
                  <TD>
                    <CategoryBadge category={r.category} />
                  </TD>
                  <TD className="text-right tabular-nums">{r.hits}</TD>
                  <TD className="text-right tabular-nums">{r.devices}</TD>
                  <TD>{relativeTime(r.lastSeen)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
