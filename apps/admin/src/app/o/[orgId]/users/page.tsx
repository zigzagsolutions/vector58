import { TENANT_ROLES, canAssignRole } from '@bsp/auth-permissions';
import { addUserAction, removeUserAction } from '@/app/actions/tenant';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { PageHeader } from '@/components/page';
import { RoleSelect } from '@/components/role-select';
import { StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { formatDateTime } from '@/lib/utils';
import { tenantPage } from '@/server/page-guards';
import { listTenantUsers } from '@/server/services/tenant-users';

export default async function TenantUsersPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId, 'tenant.users.read');
  const users = await listTenantUsers(actor);
  const canWrite = actor.permissions.has('tenant.users.write');
  // Only offer roles the actor may grant (server re-checks).
  const assignable = Object.values(TENANT_ROLES).filter((r) => canAssignRole(actor.permissions, r));
  return (
    <>
      <PageHeader title="Users" description="People with access to this organization and their roles." />
      <div className="grid gap-5 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <Table>
            <THead><TR><TH>User</TH><TH>Role</TH><TH>Status</TH><TH>Added</TH><TH /></TR></THead>
            <TBody>
              {users.map((u) => (
                <TR key={u.userId}>
                  <TD>{u.displayName ?? u.email}<div className="text-xs text-muted">{u.email}</div></TD>
                  <TD>{canWrite && u.userId !== actor.user.id ? <RoleSelect orgId={orgId} userId={u.userId} current={u.roles[0] ?? ''} roles={assignable.map((r) => ({ key: r.key, name: r.name }))} /> : u.roles.join(', ')}</TD>
                  <TD><StatusBadge status={u.status} /></TD>
                  <TD>{formatDateTime(u.addedAt)}</TD>
                  <TD>{canWrite && u.userId !== actor.user.id ? <ActionButton label="Remove" variant="ghost" confirm={`Remove ${u.email} from this organization?`} action={removeUserAction.bind(null, orgId, u.userId)} /> : null}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Card>
        {canWrite ? (
          <Card>
            <CardHeader><CardTitle>Add user</CardTitle></CardHeader>
            <CardContent>
              <ActionForm action={addUserAction.bind(null, orgId)} submitLabel="Add user">
                <Field label="Email" htmlFor="email"><Input id="email" name="email" type="email" required /></Field>
                <Field label="Role" htmlFor="roleKey" hint="You can only grant roles within your own permissions.">
                  <Select id="roleKey" name="roleKey">{assignable.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}</Select>
                </Field>
              </ActionForm>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </>
  );
}
