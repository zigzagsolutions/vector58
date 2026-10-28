import Link from 'next/link';
import { PageHeader } from '@/components/page';
import { RuleForm } from '@/components/rule-form';
import { Card, CardContent } from '@/components/ui/card';
import { tenantPage } from '@/server/page-guards';
import { getPolicyDetail } from '@/server/services/policies';

export default async function AddBlockRulePage({
  params,
}: {
  params: Promise<{ orgId: string; policyId: string }>;
}) {
  const { orgId, policyId } = await params;
  const actor = await tenantPage(orgId, 'tenant.policy.write');
  const { policy } = await getPolicyDetail(actor, policyId);
  return (
    <>
      <PageHeader
        title="Add Block Rule"
        description={`Policy: ${policy.name}. Rules take effect on endpoints after the policy is published.`}
      />
      <Card className="max-w-xl">
        <CardContent>
          <RuleForm orgId={orgId} policyId={policyId} mode="block" />
        </CardContent>
      </Card>
      <Link
        href={`/o/${orgId}/policies/${policyId}`}
        className="mt-4 inline-block text-sm text-primary hover:underline"
      >
        ← Back to policy
      </Link>
    </>
  );
}
