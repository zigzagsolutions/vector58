import { EndpointCommandTypeSchema } from '@bsp/policy-types';
import { issueCommandAction, setDeviceStatusAction } from '@/app/actions/tenant';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { EmptyState, Mono, PageHeader } from '@/components/page';
import { CategoryBadge, ProtectionBadge, StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Select } from '@/components/ui/form';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime, relativeTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { getDevice } from '@/server/services/devices';

export default async function DeviceDetailPage({ params }: { params: Promise<{ orgId: string; deviceId: string }> }) {
  const { orgId, deviceId } = await params;
  const actor = await tenantPage(orgId, 'tenant.devices.read');
  const { device: d, recentEvents, commands } = await getDevice(actor, deviceId);
  const canManage = actor.permissions.has('tenant.devices.manage');
  const facts: [string, React.ReactNode][] = [
    ['Device ID', <Mono key="id">{d.id}</Mono>],
    ['Organization', actor.organizationName],
    ['OS', d.osVersion ?? '—'],
    ['Local IP', d.localIp ?? '—'],
    ['Public IP (server-observed)', d.publicIp ?? '—'],
    ['Agent version', d.agentVersion ?? '—'],
    ['Chrome extension', d.chrome?.extensionVersion ?? 'not reporting'],
    ['Edge extension', d.edge?.extensionVersion ?? 'not reporting'],
    ['Current policy version', d.policyVersion !== null ? `v${d.policyVersion}` : '—'],
    ['Last heartbeat', `${formatDateTime(d.lastHeartbeatAt)} (${relativeTime(d.lastHeartbeatAt)})`],
    ['Enrolled', formatDateTime(d.enrolledAt)],
  ];
  return (
    <>
      <PageHeader
        title={d.hostname}
        description="Device detail"
        actions={
          <>
            <ProtectionBadge status={d.protection} />
            {canManage && d.status === 'active' ? (
              <ActionButton variant="danger" size="sm" label="Disable device" confirm="Disable this device? Its credential stops working; the browser keeps enforcing cached rules." action={setDeviceStatusAction.bind(null, orgId, d.id, 'disabled')} />
            ) : null}
          </>
        }
      />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Endpoint</CardTitle></CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
              {facts.map(([k, v]) => (
                <div key={k}><dt className="text-xs text-muted">{k}</dt><dd>{v}</dd></div>
              ))}
            </dl>
          </CardContent>
        </Card>
        {canManage ? (
          <Card>
            <CardHeader><CardTitle>Send command</CardTitle></CardHeader>
            <CardContent>
              <ActionForm action={issueCommandAction.bind(null, orgId)} submitLabel="Queue command">
                <input type="hidden" name="deviceId" value={d.id} />
                <Field label="Command" htmlFor="commandType">
                  <Select id="commandType" name="commandType">
                    {EndpointCommandTypeSchema.options.filter((c) => c !== 'COLLECT_BROWSER_HISTORY').map((c) => <option key={c}>{c}</option>)}
                  </Select>
                </Field>
              </ActionForm>
            </CardContent>
          </Card>
        ) : null}
      </div>
      <Card className="mt-5">
        <CardHeader><CardTitle>Browser clients</CardTitle></CardHeader>
        {d.browserClients.length === 0 ? <EmptyState title="No browser extension has reported" description="Load the extension in Chrome or Edge and register the native messaging host." /> : (
          <Table>
            <THead><TR><TH>Browser</TH><TH>Version</TH><TH>Extension</TH><TH>Native messaging</TH><TH>Applied policy</TH><TH>DNR rules</TH><TH>Last seen</TH></TR></THead>
            <TBody>
              {d.browserClients.map((c) => (
                <TR key={c.clientId}>
                  <TD className="capitalize">{c.browser}</TD><TD>{c.browserVersion ?? '—'}</TD><TD>{c.extensionVersion ?? '—'}</TD>
                  <TD><StatusBadge status={c.nativeConnected ? 'active' : 'disabled'} /></TD>
                  <TD>{c.policyVersion !== null ? `v${c.policyVersion}` : '—'}</TD><TD className="tabular-nums">{c.dnrRuleCount ?? '—'}</TD><TD>{relativeTime(c.lastSeenAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Recent events</CardTitle></CardHeader>
          {recentEvents.length === 0 ? <EmptyState title="No events" /> : (
            <Table>
              <THead><TR><TH>When</TH><TH>Type</TH><TH>Domain</TH><TH>Category</TH></TR></THead>
              <TBody>{recentEvents.map((e) => <TR key={e.id}><TD>{relativeTime(e.occurredAt)}</TD><TD className="font-mono text-xs">{e.eventType}</TD><TD className="font-mono text-xs">{e.domain ?? '—'}</TD><TD><CategoryBadge category={e.threatCategory} /></TD></TR>)}</TBody>
            </Table>
          )}
        </Card>
        <Card>
          <CardHeader><CardTitle>Commands</CardTitle></CardHeader>
          {commands.length === 0 ? <EmptyState title="No commands issued" /> : (
            <Table>
              <THead><TR><TH>Issued</TH><TH>Command</TH><TH>Status</TH></TR></THead>
              <TBody>{commands.map((c) => <TR key={c.id}><TD>{relativeTime(c.issuedAt)}</TD><TD className="font-mono text-xs">{c.commandType}</TD><TD><StatusBadge status={c.status} />{c.error ? <div className="text-xs text-danger">{c.error}</div> : null}</TD></TR>)}</TBody>
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
