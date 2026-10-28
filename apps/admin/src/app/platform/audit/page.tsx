import { AuditTable } from '@/components/audit-table';
import { PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { Card } from '@/components/ui/card';
import { platformPage } from '@/server/page-guards';
import { listPlatformAudit } from '@/server/services/audit-log';
import { listOrganizations } from '@/server/services/organizations';

export default async function PlatformAuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const actor = await platformPage('platform.audit.read');
  const sp = await searchParams;
  const orgs = actor.permissions.has('platform.tenants.read') ? await listOrganizations(actor) : [];
  const uuid = /^[0-9a-f-]{36}$/i;
  const rows = await listPlatformAudit(actor, {
    organizationId:
      sp.organizationId && uuid.test(sp.organizationId) ? sp.organizationId : undefined,
    action: sp.action || undefined,
    scope: sp.scope || undefined,
  });
  return (
    <>
      <PageHeader
        title="Audit"
        description="Append-only record of privileged actions across all tenants."
      />
      <Card>
        <SearchForm
          values={sp}
          fields={[
            {
              name: 'organizationId',
              label: 'Tenant',
              type: 'select',
              options: orgs.map((o) => ({ value: o.id, label: o.name })),
            },
            { name: 'action', label: 'Action', placeholder: 'e.g. PLATFORM_ADMIN_ENTERED_TENANT' },
            {
              name: 'scope',
              label: 'Actor scope',
              type: 'select',
              options: ['platform', 'tenant', 'device', 'system'].map((v) => ({
                value: v,
                label: v,
              })),
            },
          ]}
        />
        <AuditTable rows={rows} showTenant />
      </Card>
    </>
  );
}
