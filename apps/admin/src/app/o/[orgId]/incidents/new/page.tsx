import { createIncidentAction } from '@/app/actions/tenant';
import { ActionForm } from '@/components/action-form';
import { PageHeader } from '@/components/page';
import { Card, CardContent } from '@/components/ui/card';
import { Field, Input, Select, Textarea } from '@/components/ui/form';
import { tenantPage } from '@/server/page-guards';

export default async function NewIncidentPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  await tenantPage(orgId, 'tenant.incident.create');
  return (
    <>
      <PageHeader title="Create Incident" />
      <Card className="max-w-xl">
        <CardContent>
          <ActionForm action={createIncidentAction.bind(null, orgId)} submitLabel="Create incident">
            <Field label="Title" htmlFor="title">
              <Input id="title" name="title" required minLength={3} maxLength={200} />
            </Field>
            <Field label="Severity" htmlFor="severity">
              <Select id="severity" name="severity" defaultValue="medium">
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </Select>
            </Field>
            <Field label="Description" htmlFor="description">
              <Textarea id="description" name="description" maxLength={5000} />
            </Field>
          </ActionForm>
        </CardContent>
      </Card>
    </>
  );
}
