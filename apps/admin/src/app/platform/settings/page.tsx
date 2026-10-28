import { PERMISSION_DESCRIPTIONS } from '@bsp/auth-permissions';
import { PageHeader } from '@/components/page';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { platformPage } from '@/server/page-guards';

export default async function PlatformSettingsPage() {
  const actor = await platformPage();
  return (
    <>
      <PageHeader title="Settings" description="Your platform identity and effective permissions." />
      <Card className="max-w-2xl">
        <CardHeader><CardTitle>{actor.user.email}</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div><span className="text-muted">Platform roles:</span> {actor.platformRoles.join(', ')}</div>
          <ul className="space-y-1">
            {[...actor.permissions].sort().map((p) => (
              <li key={p}><code className="text-xs">{p}</code> <span className="text-muted">— {PERMISSION_DESCRIPTIONS[p]}</span></li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </>
  );
}
