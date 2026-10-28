import { Shell } from '@/components/shell';
import { PLATFORM_NAV, visibleNav } from '@/lib/navigation';
import { getAuthorizer } from '@/server/auth';
import { platformPage } from '@/server/page-guards';

export const dynamic = 'force-dynamic';

export default async function PlatformLayout({ children }: { children: React.ReactNode }) {
  const actor = await platformPage();
  const orgs = await getAuthorizer().myOrganizations();
  return (
    <Shell
      title="Vector58 Platform"
      subtitle={actor.platformRoles.join(', ')}
      nav={visibleNav(PLATFORM_NAV, actor.permissions)}
      userEmail={actor.user.email}
      switcher={orgs.map((o) => ({ href: `/o/${o.id}`, label: `${o.name} (member)` }))}
    >
      {children}
    </Shell>
  );
}
