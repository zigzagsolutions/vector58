import { Shell } from '@/components/shell';
import { tenantNav, visibleNav } from '@/lib/navigation';
import { getAuthorizer } from '@/server/auth';
import { tenantPage } from '@/server/page-guards';

export const dynamic = 'force-dynamic';

export default async function TenantLayout({ children, params }: { children: React.ReactNode; params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const actor = await tenantPage(orgId);
  const authz = getAuthorizer();
  const ctx = actor.via === 'platform_context' ? await authz.resolveTenantContext() : null;
  const orgs = actor.via === 'membership' ? await authz.myOrganizations() : [];
  return (
    <Shell
      title={actor.organizationName}
      subtitle={actor.via === 'platform_context' ? `Platform: ${actor.platformRoles.join(', ')}` : actor.tenantRoles.join(', ')}
      nav={visibleNav(tenantNav(orgId), actor.permissions)}
      userEmail={actor.user.email}
      tenantBanner={ctx ? { organizationName: ctx.organizationName, expiresAt: ctx.expiresAt } : null}
      switcher={orgs.filter((o) => o.id !== orgId).map((o) => ({ href: `/o/${o.id}`, label: o.name }))}
    >
      {children}
    </Shell>
  );
}
