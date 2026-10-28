import Link from 'next/link';
import { Metric, PageHeader } from '@/components/page';
import { CategoryBadge } from '@/components/status';
import { Card, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { EmptyState } from '@/components/page';
import { relativeTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { tenantDashboard } from '@/server/services/dashboard';

export default async function TenantOverviewPage({
  params,
}: {
  params: Promise<{ orgId: string }>;
}) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId);
  const d = await tenantDashboard(actor);
  return (
    <>
      <PageHeader
        title="Overview"
        description={`Security posture for ${actor.organizationName}.`}
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric
          label="Active Devices"
          value={d.activeDevices}
          hint={d.totalDevices !== null ? `${d.totalDevices} enrolled` : undefined}
        />
        <Metric label="Protected Devices" value={d.protectedDevices} tone="success" />
        <Metric
          label="Outdated Devices"
          value={d.outdatedDevices}
          tone={d.outdatedDevices ? 'warning' : undefined}
        />
        <Metric
          label="Blocked Events Today"
          value={d.blockedToday}
          tone={d.blockedToday ? 'danger' : undefined}
        />
        <Metric label="Active Policies" value={d.activePolicies} />
        <Metric
          label="Latest Policy Version"
          value={d.latestPolicyVersion ? `v${d.latestPolicyVersion}` : 'unpublished'}
        />
        <Metric
          label="Open Incidents"
          value={d.openIncidents}
          tone={d.openIncidents ? 'warning' : undefined}
        />
      </div>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>Recent threat events</CardTitle>
          <Link href={`/o/${orgId}/events`} className="text-xs text-primary">
            All events
          </Link>
        </CardHeader>
        {d.recentThreatEvents.length === 0 ? (
          <EmptyState
            title="No blocked navigations yet"
            description="Blocked navigations reported by endpoints appear here within a minute."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>When</TH>
                <TH>Device</TH>
                <TH>Domain</TH>
                <TH>Category</TH>
                <TH>Browser</TH>
              </TR>
            </THead>
            <TBody>
              {d.recentThreatEvents.map((e) => (
                <TR key={e.id}>
                  <TD>{relativeTime(e.occurredAt)}</TD>
                  <TD>{e.hostname}</TD>
                  <TD className="font-mono text-xs">{e.domain}</TD>
                  <TD>
                    <CategoryBadge category={e.category} />
                  </TD>
                  <TD>{e.browser}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
