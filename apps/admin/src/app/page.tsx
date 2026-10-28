import { isAppError } from '@bsp/shared';
import { redirect } from 'next/navigation';
import { getAuthorizer } from '@/server/auth';

export const dynamic = 'force-dynamic';

/** Route users to their home: platform console, tenant context, or their organization. */
export default async function Home() {
  const authz = getAuthorizer();
  try {
    const user = await authz.requireAuthenticatedUser();
    const ctx = await authz.resolveTenantContext();
    if (ctx) redirect(`/o/${ctx.organizationId}`);
    const platform = await authz.platformAccess(user);
    if (platform.roles.length > 0) redirect('/platform');
    const orgs = await authz.myOrganizations();
    if (orgs[0]) redirect(`/o/${orgs[0].id}`);
  } catch (e) {
    if (isAppError(e) && e.code === 'UNAUTHENTICATED') redirect('/login');
    throw e;
  }
  return (
    <main className="flex min-h-screen items-center justify-center p-6 text-center">
      <div>
        <h1 className="text-lg font-semibold">No organization access</h1>
        <p className="mt-1 text-sm text-muted">
          Your account is not a member of any organization yet. Contact your administrator.
        </p>
        <form action="/auth/signout" method="post" className="mt-4">
          <button className="text-sm text-primary">Sign out</button>
        </form>
      </div>
    </main>
  );
}
