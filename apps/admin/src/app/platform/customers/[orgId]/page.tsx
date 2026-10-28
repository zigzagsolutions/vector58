import { TENANT_ROLES } from '@bsp/auth-permissions';
import { assignTenantUserAction, enterTenantAction, setCustomerStatusAction } from '@/app/actions/platform';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { EmptyState, Mono, PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { platformPage } from '@/server/page-guards';
import { getOrganization } from '@/server/services/organizations';
import { listTenantUsersForPlatform } from '@/server/services/tenant-users';

export default async function CustomerDetailPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await platformPage('platform.tenants.read');
  const org = await getOrganization(actor, orgId);
  const users = actor.permissions.has('platform.users.read') ? await listTenantUsersForPlatform(actor, orgId) : null;
  const can = (p: Parameters<typeof actor.permissions.has>[0]) => actor.permissions.has(p);

  return (
    <>
      <PageHeader
        title={org.name}
        description={`Tenant ${org.slug} · created ${formatDateTime(org.createdAt)}`}
        actions={
          <>
            <StatusBadge status={org.status} />
            {can('platform.tenants.manage') ? (
              org.status === 'active' ? (
                <ActionButton variant="danger" size="sm" label="Disable tenant" confirm={`Disable ${org.name}? Its users lose access immediately; devices keep enforcing cached policy.`} action={setCustomerStatusAction.bind(null, org.id, 'disabled')} />
              ) : (
                <ActionButton size="sm" label="Re-enable tenant" action={setCustomerStatusAction.bind(null, org.id, 'active')} />
              )
            ) : null}
          </>
        }
      />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Tenant users</CardTitle></CardHeader>
          {users === null ? (
            <CardContent className="text-sm text-muted">Your platform role cannot view tenant user directories.</CardContent>
          ) : users.length === 0 ? (
            <EmptyState title="No users yet" description="Assign a tenant administrator to get this customer started." />
          ) : (
            <Table>
              <THead><TR><TH>User</TH><TH>Roles</TH><TH>Status</TH><TH>Added</TH></TR></THead>
              <TBody>
                {users.map((u) => (
                  <TR key={u.userId}><TD>{u.email}</TD><TD>{u.roles.join(', ')}</TD><TD><StatusBadge status={u.status} /></TD><TD>{formatDateTime(u.addedAt)}</TD></TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
        <div className="space-y-5">
          {can('platform.support.enter_tenant') ? (
            <Card>
              <CardHeader><CardTitle>Enter tenant context</CardTitle></CardHeader>
              <CardContent>
                <p className="mb-3 text-xs text-muted">
                  You keep your own identity. Access is limited by your platform role, expires automatically, and is recorded in this
                  customer&apos;s audit log as PLATFORM_ADMIN_ENTERED_TENANT.
                </p>
                <ActionForm action={enterTenantAction.bind(null, org.id)} submitLabel={`Enter ${org.name}`}>
                  <Field label="Reason (recorded in audit)" htmlFor="reason"><Input id="reason" name="reason" placeholder="e.g. Support ticket #1234" /></Field>
                </ActionForm>
              </CardContent>
            </Card>
          ) : null}
          {can('platform.users.manage') ? (
            <Card>
              <CardHeader><CardTitle>Assign tenant user</CardTitle></CardHeader>
              <CardContent>
                <ActionForm action={assignTenantUserAction.bind(null, org.id)} submitLabel="Add user">
                  <Field label="Email" htmlFor="email"><Input id="email" name="email" type="email" required /></Field>
                  <Field label="Role" htmlFor="roleKey">
                    <Select id="roleKey" name="roleKey" defaultValue="TenantSecurityAdmin">
                      {Object.values(TENANT_ROLES).map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}
                    </Select>
                  </Field>
                </ActionForm>
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardHeader><CardTitle>Identifiers</CardTitle></CardHeader>
            <CardContent className="space-y-1 text-xs"><div>Organization ID</div><Mono>{org.id}</Mono></CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
