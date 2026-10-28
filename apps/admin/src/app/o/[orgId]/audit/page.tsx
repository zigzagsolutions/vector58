import { AuditTable } from '@/components/audit-table';
import { PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { Card } from '@/components/ui/card';
import { tenantPage } from '@/server/page-guards';
import { listTenantAudit } from '@/server/services/audit-log';

export default async function TenantAuditPage({ params, searchParams }: { params: Promise<{ orgId: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const { orgId } = await params;
  const sp = await searchParams;
  const actor = await tenantPage(orgId, 'tenant.audit.read');
  const rows = await listTenantAudit(actor, { action: sp.action || undefined });
  return (
    <>
      <PageHeader title="Audit Log" description="Every administrative action in this organization, including platform staff who entered your tenant." />
      <Card>
        <SearchForm values={sp} fields={[{ name: 'action', label: 'Action', placeholder: 'e.g. POLICY_PUBLISHED' }]} />
        <AuditTable rows={rows} />
      </Card>
    </>
  );
}
