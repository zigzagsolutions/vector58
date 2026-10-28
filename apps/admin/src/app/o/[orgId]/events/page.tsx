import { SecurityEventTypeSchema, ThreatCategorySchema } from '@bsp/policy-types';
import Link from 'next/link';
import { EmptyState, PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { CategoryBadge } from '@/components/status';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { parseWith } from '@/server/http';
import { tenantPage } from '@/server/page-guards';
import { listDevices } from '@/server/services/devices';
import { EventFiltersSchema, listSecurityEvents } from '@/server/services/events';

export default async function SecurityEventsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgId: string }>;
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const { orgId } = await params;
  const sp = await searchParams;
  const actor = await tenantPage(orgId, 'tenant.events.read');
  const clean = Object.fromEntries(Object.entries(sp).filter(([, v]) => v));
  const filters = parseWith(EventFiltersSchema, { range: '7d', ...clean });
  const [events, devices] = await Promise.all([
    listSecurityEvents(actor, filters),
    actor.permissions.has('tenant.devices.read') ? listDevices(actor) : Promise.resolve([]),
  ]);
  return (
    <>
      <PageHeader
        title="Security Events"
        description="Events reported by endpoints. Tenant and device are derived from the authenticated device, never from the event body."
      />
      <Card>
        <SearchForm
          values={{ range: '7d', ...sp }}
          fields={[
            {
              name: 'range',
              label: 'Time range',
              type: 'select',
              options: [
                { value: '1h', label: 'Last hour' },
                { value: '24h', label: 'Last 24h' },
                { value: '7d', label: 'Last 7 days' },
                { value: '30d', label: 'Last 30 days' },
              ],
            },
            {
              name: 'eventType',
              label: 'Event',
              type: 'select',
              options: SecurityEventTypeSchema.options.map((v) => ({ value: v, label: v })),
            },
            {
              name: 'deviceId',
              label: 'Device',
              type: 'select',
              options: devices.map((d) => ({ value: d.id, label: d.hostname })),
            },
            { name: 'hostname', label: 'Hostname', placeholder: 'WIN-…' },
            { name: 'domain', label: 'Domain', placeholder: 'example.com' },
            {
              name: 'category',
              label: 'Threat category',
              type: 'select',
              options: ThreatCategorySchema.options.map((v) => ({ value: v, label: v })),
            },
            { name: 'policyVersion', label: 'Policy version', placeholder: 'e.g. 3' },
          ]}
        />
        {events.length === 0 ? (
          <EmptyState title="No events match these filters" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Time</TH>
                <TH>Event</TH>
                <TH>Device</TH>
                <TH>Destination</TH>
                <TH>Category</TH>
                <TH>Browser</TH>
                <TH>Policy</TH>
                <TH>Rule</TH>
              </TR>
            </THead>
            <TBody>
              {events.map((e) => (
                <TR key={e.id}>
                  <TD className="whitespace-nowrap text-xs">{formatDateTime(e.occurredAt)}</TD>
                  <TD>
                    <Badge
                      tone={
                        e.eventType === 'URL_BLOCKED'
                          ? 'danger'
                          : e.eventType === 'POLICY_FAILED'
                            ? 'warning'
                            : 'neutral'
                      }
                    >
                      {e.eventType}
                    </Badge>
                    {e.verified === false ? (
                      <div className="text-[11px] text-amber-700">unverified</div>
                    ) : null}
                  </TD>
                  <TD>
                    {e.deviceId ? (
                      <Link
                        className="text-primary hover:underline"
                        href={`/o/${orgId}/devices/${e.deviceId}`}
                      >
                        {e.hostname}
                      </Link>
                    ) : (
                      (e.hostname ?? '—')
                    )}
                  </TD>
                  <TD
                    className="max-w-80 truncate font-mono text-xs"
                    title={e.url ?? e.domain ?? ''}
                  >
                    {e.url ?? e.domain ?? '—'}
                  </TD>
                  <TD>
                    <CategoryBadge category={e.threatCategory} />
                  </TD>
                  <TD className="text-xs">
                    {e.browser ? `${e.browser} ${e.browserVersion ?? ''}` : '—'}
                    {e.extensionVersion ? (
                      <div className="text-muted">ext {e.extensionVersion}</div>
                    ) : null}
                  </TD>
                  <TD className="tabular-nums">
                    {e.policyVersion !== null ? `v${e.policyVersion}` : '—'}
                  </TD>
                  <TD className="font-mono text-xs">{e.ruleId ?? '—'}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
