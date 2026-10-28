import { createEnrollmentTokenAction, revokeEnrollmentTokenAction } from '@/app/actions/tenant';
import { ActionButton } from '@/components/action-button';
import { EmptyState, Mono, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { TokenForm } from '@/components/token-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { listEnrollmentTokens } from '@/server/services/enrollment';

export default async function TenantSettingsPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.settings.read');
  const tokens = await listEnrollmentTokens(actor);
  const canManage = actor.permissions.has('tenant.devices.manage');
  return (
    <>
      <PageHeader title="Settings" description="Organization configuration and endpoint enrollment." />
      <div className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle>Enrollment tokens</CardTitle></CardHeader>
          {tokens.length === 0 ? <EmptyState title="No enrollment tokens" /> : (
            <Table>
              <THead><TR><TH>Token</TH><TH>Description</TH><TH>Uses</TH><TH>Expires</TH><TH>Status</TH><TH /></TR></THead>
              <TBody>
                {tokens.map((t) => (
                  <TR key={t.id}>
                    <TD><Mono>{t.tokenPrefix}…</Mono></TD><TD>{t.description ?? '—'}</TD><TD className="tabular-nums">{t.useCount}/{t.maxUses}</TD>
                    <TD className="text-xs">{formatDateTime(t.expiresAt)}</TD><TD><StatusBadge status={t.status} /></TD>
                    <TD>{canManage && t.status === 'active' ? <ActionButton label="Revoke" variant="ghost" confirm="Revoke this token? Already-enrolled devices are unaffected." action={revokeEnrollmentTokenAction.bind(null, orgId, t.id)} /> : null}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
        <div className="space-y-5">
          {canManage ? <Card><CardHeader><CardTitle>Create enrollment token</CardTitle></CardHeader><CardContent><TokenForm action={createEnrollmentTokenAction.bind(null, orgId)} /></CardContent></Card> : null}
          <Card>
            <CardHeader><CardTitle>Organization</CardTitle></CardHeader>
            <CardContent className="space-y-1 text-sm"><div>{actor.organizationName}</div><Mono>{actor.organizationId}</Mono></CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
