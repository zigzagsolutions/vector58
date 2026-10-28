import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { ProtectionBadge } from '@/components/status';
import { buttonVariants } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { listDevices } from '@/server/services/devices';

const PROTECTION_OPTIONS = [
  'protected',
  'degraded',
  'policy_outdated',
  'offline',
  'never_enrolled',
].map((v) => ({ value: v, label: v }));

export default async function DevicesPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgId: string }>;
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const { orgId } = await params;
  const sp = await searchParams;
  const actor = await tenantPage(orgId, 'tenant.devices.read');
  const q = sp.q?.toLowerCase();
  const devices = (await listDevices(actor)).filter(
    (d) =>
      (!q || d.hostname.toLowerCase().includes(q) || d.id.startsWith(q)) &&
      (!sp.protection || d.protection === sp.protection),
  );
  return (
    <>
      <PageHeader
        title="Devices"
        description="Windows endpoints enrolled in this organization."
        actions={
          actor.permissions.has('tenant.settings.read') ? (
            <Link href={`/o/${orgId}/settings`} className={buttonVariants({ variant: 'outline' })}>
              Enrollment tokens
            </Link>
          ) : null
        }
      />
      <Card>
        <SearchForm
          values={sp}
          fields={[
            { name: 'q', label: 'Hostname', placeholder: 'Search hostname' },
            { name: 'protection', label: 'Status', type: 'select', options: PROTECTION_OPTIONS },
          ]}
        />
        {devices.length === 0 ? (
          <EmptyState
            title="No devices"
            description="Create an enrollment token under Settings and install the Windows agent with it."
          />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Hostname</TH>
                <TH>Status</TH>
                <TH>OS</TH>
                <TH>Agent</TH>
                <TH>Chrome</TH>
                <TH>Edge</TH>
                <TH>Policy</TH>
                <TH>Last heartbeat</TH>
              </TR>
            </THead>
            <TBody>
              {devices.map((d) => (
                <TR key={d.id}>
                  <TD>
                    <Link
                      className="font-medium text-primary hover:underline"
                      href={`/o/${orgId}/devices/${d.id}`}
                    >
                      {d.hostname}
                    </Link>
                  </TD>
                  <TD>
                    <ProtectionBadge status={d.protection} />
                  </TD>
                  <TD className="max-w-48 truncate" title={d.osVersion ?? ''}>
                    {d.osVersion ?? '—'}
                  </TD>
                  <TD className="font-mono text-xs">{d.agentVersion ?? '—'}</TD>
                  <TD className="text-xs">
                    {d.chrome
                      ? `${d.chrome.extensionVersion ?? '?'} · v${d.chrome.policyVersion ?? '–'}${d.chrome.nativeConnected ? '' : ' (disconnected)'}`
                      : '—'}
                  </TD>
                  <TD className="text-xs">
                    {d.edge
                      ? `${d.edge.extensionVersion ?? '?'} · v${d.edge.policyVersion ?? '–'}${d.edge.nativeConnected ? '' : ' (disconnected)'}`
                      : '—'}
                  </TD>
                  <TD className="tabular-nums">
                    {d.policyVersion !== null ? `v${d.policyVersion}` : '—'}
                  </TD>
                  <TD>{relativeTime(d.lastHeartbeatAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
