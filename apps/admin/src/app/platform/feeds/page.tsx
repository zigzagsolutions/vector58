import { syncFeedAction } from '@/app/actions/platform';
import { ActionButton } from '@/components/action-button';
import { PageHeader } from '@/components/page';
import { StatusBadge } from '@/components/status';
import { Card } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { platformPage } from '@/server/page-guards';
import { listThreatSources } from '@/server/services/threats';

export default async function ThreatFeedsPage() {
  const actor = await platformPage('platform.security.threats.read');
  const sources = await listThreatSources(actor);
  const canManage = actor.permissions.has('platform.security.threats.manage');
  return (
    <>
      <PageHeader
        title="Threat Feeds"
        description="Pipeline: fetch → validate → normalize → deduplicate → score → store observation → update indicator → expire stale."
      />
      <Card>
        <Table>
          <THead>
            <TR>
              <TH>Source</TH>
              <TH>Type</TH>
              <TH>Enabled</TH>
              <TH className="text-right">Indicators</TH>
              <TH>Last sync</TH>
              <TH>Status</TH>
              <TH>Last run</TH>
              <TH />
            </TR>
          </THead>
          <TBody>
            {sources.map((s) => (
              <TR key={s.id}>
                <TD className="font-medium">{s.name}</TD>
                <TD>{s.sourceType}</TD>
                <TD>{s.enabled ? 'Yes' : 'No'}</TD>
                <TD className="text-right tabular-nums">{s.indicators}</TD>
                <TD>{relativeTime(s.lastSync)}</TD>
                <TD>
                  <StatusBadge status={s.syncStatus} />
                  {s.lastError ? (
                    <div className="mt-1 max-w-xs text-xs text-danger">{s.lastError}</div>
                  ) : null}
                </TD>
                <TD className="text-xs text-muted">
                  {s.lastStats
                    ? Object.entries(s.lastStats)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(' · ')
                    : '—'}
                </TD>
                <TD>
                  {canManage && s.sourceType !== 'manual' ? (
                    <ActionButton label="Sync now" action={syncFeedAction.bind(null, s.id)} />
                  ) : null}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </Card>
      <p className="mt-3 text-xs text-muted">
        Provider interfaces exist for URLhaus, OpenPhish, PhishTank, commercial and internal feeds.
        Only the sample feed is enabled in Phase 1; credentials are never stored in the database.
      </p>
    </>
  );
}
