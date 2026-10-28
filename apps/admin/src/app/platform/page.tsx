import Link from 'next/link';
import { Metric, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { platformPage } from '@/server/page-guards';
import { listPlatformAudit } from '@/server/services/audit-log';
import { platformDashboard } from '@/server/services/dashboard';

export default async function PlatformDashboardPage() {
  const actor = await platformPage();
  const d = await platformDashboard(actor);
  const audit = actor.permissions.has('platform.audit.read') ? await listPlatformAudit(actor, { limit: 8 }) : [];
  return (
    <>
      <PageHeader title="Platform Dashboard" description="Fleet-wide health across all customer tenants." />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Metric label="Active Tenants" value={d.activeTenants} hint={`${d.totalTenants} total`} />
        <Metric label="Enrolled Devices" value={d.totalDevices} />
        <Metric label="Online Devices" value={d.onlineDevices} tone={d.onlineDevices < d.totalDevices ? 'warning' : 'success'} />
        <Metric label="Blocked Today" value={d.blockedToday} />
        <Metric label="Active Indicators" value={d.activeIndicators} />
      </div>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Threat feeds</CardTitle><Link className="text-xs text-primary" href="/platform/feeds">Manage</Link></CardHeader>
          <Table>
            <THead><TR><TH>Source</TH><TH>Type</TH><TH>Status</TH><TH>Last sync</TH></TR></THead>
            <TBody>
              {d.feeds.map((f) => (
                <TR key={f.name}><TD>{f.name}</TD><TD>{f.sourceType}</TD><TD><StatusBadge status={f.syncStatus} /></TD><TD>{relativeTime(f.lastSync)}</TD></TR>
              ))}
            </TBody>
          </Table>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent platform audit</CardTitle><Link className="text-xs text-primary" href="/platform/audit">View all</Link></CardHeader>
          {audit.length ? (
            <Table>
              <THead><TR><TH>When</TH><TH>Action</TH><TH>Actor</TH><TH>Tenant</TH></TR></THead>
              <TBody>
                {audit.map((a) => (
                  <TR key={a.id}><TD>{relativeTime(a.occurredAt)}</TD><TD className="font-mono text-xs">{a.action}</TD><TD>{a.actorEmail ?? a.actorScope}</TD><TD>{a.organizationName ?? '—'}</TD></TR>
                ))}
              </TBody>
            </Table>
          ) : <CardContent className="text-sm text-muted">No audit access or no entries.</CardContent>}
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader><CardTitle>Agent versions in the field</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap gap-3 text-sm">
          {d.agentVersions.length ? d.agentVersions.map((a) => <span key={a.version} className="rounded border border-border px-2 py-1 font-mono text-xs">{a.version}: {a.count}</span>) : <span className="text-muted">No enrolled agents yet.</span>}
        </CardContent>
      </Card>
    </>
  );
}
