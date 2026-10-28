import { Metric, PageHeader } from '@/components/page';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { platformPage } from '@/server/page-guards';
import { platformDashboard, systemHealth } from '@/server/services/dashboard';

export default async function SystemHealthPage() {
  const actor = await platformPage('platform.tenants.read');
  const [health, d] = await Promise.all([systemHealth(), platformDashboard(actor)]);
  return (
    <>
      <PageHeader title="System Health" description="Control-plane status. Endpoints keep enforcing cached policy if the control plane is unavailable." />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Database" value={health.database === 'ok' ? 'Healthy' : 'Error'} tone={health.database === 'ok' ? 'success' : 'danger'} hint={`${health.latencyMs} ms`} />
        <Metric label="API version" value="v1" />
        <Metric label="Online devices" value={`${d.onlineDevices}/${d.totalDevices}`} />
        <Metric label="Feeds failing" value={d.feeds.filter((f) => f.syncStatus === 'failed').length} />
      </div>
      <Card className="mt-5">
        <CardHeader><CardTitle>Endpoints</CardTitle></CardHeader>
        <CardContent className="text-sm text-muted">Liveness probe: <code>/api/v1/health</code>. Scheduled maintenance: <code>/api/internal/maintenance</code> (Supabase Edge Function <code>scheduled-maintenance</code>).</CardContent>
      </Card>
    </>
  );
}
