import { createCustomerAction } from '@/app/actions/platform';
import { ActionForm } from '@/components/action-form';
import { PageHeader } from '@/components/page';
import { Card, CardContent } from '@/components/ui/card';
import { Field, Input } from '@/components/ui/form';
import { platformPage } from '@/server/page-guards';

export default async function CreateCustomerPage() {
  await platformPage('platform.tenants.manage');
  return (
    <>
      <PageHeader
        title="Create Customer"
        description="Creates the tenant and its default policy. The action is audited as TENANT_CREATED."
      />
      <Card className="max-w-lg">
        <CardContent>
          <ActionForm action={createCustomerAction} submitLabel="Create customer">
            <Field label="Organization name" htmlFor="name">
              <Input id="name" name="name" required minLength={2} maxLength={120} />
            </Field>
            <Field
              label="Slug"
              htmlFor="slug"
              hint="Lowercase letters, digits and hyphens. Used in URLs and support references."
            >
              <Input id="slug" name="slug" required pattern="[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" />
            </Field>
          </ActionForm>
        </CardContent>
      </Card>
    </>
  );
}
