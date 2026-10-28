import { EndpointCommandTypeSchema } from '@bsp/policy-types';
import { issueCommandAction } from '@/app/actions/tenant';
import { ActionForm } from '@/components/action-form';
import { EmptyState, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { requestMeta } from '@/server/http';
import { tenantPage } from '@/server/page-guards';
import { listDevices } from '@/server/services/devices';
import { getIncident } from '@/server/services/incidents';
import { headers } from 'next/headers';

export default async function IncidentDetailPage({
  params,
}: {
  params: Promise<{ orgId: string; incidentId: string }>;
}) {
  const { orgId, incidentId } = await params;
  const actor = await tenantPage(orgId, 'tenant.incident.read');
  const { incident, commands, artifacts } = await getIncident(
    actor,
    incidentId,
    requestMeta({ headers: await headers() }),
  );
  const canCommand = actor.permissions.has('tenant.incident.create');
  const canHistory =
    actor.permissions.has('tenant.incident.history.request') &&
    actor.permissions.has('tenant.incident.history.approve');
  const devices =
    canCommand && actor.permissions.has('tenant.devices.read') ? await listDevices(actor) : [];
  const types = EndpointCommandTypeSchema.options.filter(
    (t) => t !== 'COLLECT_BROWSER_HISTORY' || canHistory,
  );
  return (
    <>
      <PageHeader
        title={incident.title}
        description={`Created ${formatDateTime(incident.createdAt)} by ${incident.createdByEmail ?? 'unknown'}`}
        actions={
          <>
            <StatusBadge status={incident.severity} />
            <StatusBadge status={incident.status} />
          </>
        }
      />
      {incident.description ? (
        <Card className="mb-5">
          <CardContent className="whitespace-pre-wrap text-sm">{incident.description}</CardContent>
        </Card>
      ) : null}
      <div className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Endpoint commands</CardTitle>
            <span className="text-xs text-muted">
              PENDING → RECEIVED → RUNNING → COMPLETED / FAILED / EXPIRED
            </span>
          </CardHeader>
          {commands.length === 0 ? (
            <EmptyState title="No commands issued" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Command</TH>
                  <TH>Device</TH>
                  <TH>Status</TH>
                  <TH>Issued</TH>
                  <TH>Completed</TH>
                </TR>
              </THead>
              <TBody>
                {commands.map((c) => (
                  <TR key={c.id}>
                    <TD className="font-mono text-xs">{c.commandType}</TD>
                    <TD>{c.hostname}</TD>
                    <TD>
                      <StatusBadge status={c.status} />
                      {c.error ? <div className="text-xs text-danger">{c.error}</div> : null}
                    </TD>
                    <TD className="text-xs">{formatDateTime(c.issuedAt)}</TD>
                    <TD className="text-xs">{formatDateTime(c.completedAt)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
        {canCommand ? (
          <Card>
            <CardHeader>
              <CardTitle>Create endpoint command</CardTitle>
            </CardHeader>
            <CardContent>
              <ActionForm action={issueCommandAction.bind(null, orgId)} submitLabel="Issue command">
                <input type="hidden" name="incidentId" value={incident.id} />
                <Field label="Device" htmlFor="deviceId">
                  <Select id="deviceId" name="deviceId" required>
                    {devices.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.hostname}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Command" htmlFor="commandType">
                  <Select id="commandType" name="commandType">
                    {types.map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </Select>
                </Field>
                {canHistory ? (
                  <>
                    <Field
                      label="History window start (only for COLLECT_BROWSER_HISTORY)"
                      htmlFor="startTime"
                    >
                      <Input id="startTime" name="startTime" placeholder="2026-10-27T00:00:00Z" />
                    </Field>
                    <Field
                      label="History window end"
                      htmlFor="endTime"
                      hint="Maximum 7 days. Phase 1 agents report NOT_SUPPORTED; collection ships in Phase 2."
                    >
                      <Input id="endTime" name="endTime" placeholder="2026-10-28T00:00:00Z" />
                    </Field>
                  </>
                ) : null}
              </ActionForm>
            </CardContent>
          </Card>
        ) : null}
      </div>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>Artifacts</CardTitle>
        </CardHeader>
        {artifacts.length === 0 ? (
          <EmptyState title="No artifacts collected" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Collected</TH>
                <TH>Content</TH>
              </TR>
            </THead>
            <TBody>
              {artifacts.map((a) => (
                <TR key={a.id}>
                  <TD>{a.artifactType}</TD>
                  <TD className="text-xs">{formatDateTime(a.createdAt)}</TD>
                  <TD>
                    <pre className="max-h-48 max-w-2xl overflow-auto rounded bg-gray-50 p-2 text-[11px]">
                      {JSON.stringify(a.content, null, 2)}
                    </pre>
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
