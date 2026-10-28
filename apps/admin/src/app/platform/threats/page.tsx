import { ThreatCategorySchema } from '@bsp/policy-types';
import { createIndicatorAction, revokeIndicatorAction } from '@/app/actions/platform';
import { ActionButton } from '@/components/action-button';
import { ActionForm } from '@/components/action-form';
import { EmptyState, PageHeader } from '@/components/page';
import { SearchForm } from '@/components/search-form';
import { CategoryBadge, StatusBadge } from '@/components/status';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Select } from '@/components/ui/form';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { relativeTime } from '@/lib/utils';
import { platformPage } from '@/server/page-guards';
import { listIndicators } from '@/server/services/threats';

export default async function GlobalThreatsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const actor = await platformPage('platform.security.threats.read');
  const sp = await searchParams;
  const rows = await listIndicators(actor, { q: sp.q, status: sp.status });
  const canManage = actor.permissions.has('platform.security.threats.manage');
  return (
    <>
      <PageHeader title="Global Threats" description="Confirmed-malicious indicators compiled into every tenant policy that includes global intelligence." />
      <div className="grid gap-5 xl:grid-cols-4">
        <Card className="xl:col-span-3">
          <SearchForm values={sp} fields={[
            { name: 'q', label: 'Indicator', placeholder: 'domain or URL' },
            { name: 'status', label: 'Status', type: 'select', options: ['active', 'expired', 'revoked'].map((v) => ({ value: v, label: v })) },
          ]} />
          {rows.length === 0 ? <EmptyState title="No indicators" description="Add an indicator or sync a threat feed." /> : (
            <Table>
              <THead><TR><TH>Indicator</TH><TH>Category</TH><TH className="text-right">Confidence</TH><TH>Source</TH><TH>Last seen</TH><TH>Status</TH><TH /></TR></THead>
              <TBody>
                {rows.map((i) => (
                  <TR key={i.id}>
                    <TD className="font-mono text-xs">{i.normalizedValue}<div className="text-[11px] text-muted">{i.indicatorType} · {i.observations} observation(s)</div></TD>
                    <TD><CategoryBadge category={i.threatCategory} /></TD>
                    <TD className="text-right tabular-nums">{i.confidence}</TD>
                    <TD>{i.source}</TD>
                    <TD>{relativeTime(i.lastSeen)}</TD>
                    <TD><StatusBadge status={i.status} /></TD>
                    <TD>{canManage && i.status === 'active' ? <ActionButton label="Revoke" confirm="Revoke this indicator? It will drop out of the next published policies." action={revokeIndicatorAction.bind(null, i.id)} /> : null}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
        {canManage ? (
          <Card>
            <CardHeader><CardTitle>Add indicator</CardTitle></CardHeader>
            <CardContent>
              <ActionForm action={createIndicatorAction} submitLabel="Add">
                <Field label="Type" htmlFor="indicatorType"><Select id="indicatorType" name="indicatorType"><option value="domain">Domain</option><option value="exact_url">Exact URL</option></Select></Field>
                <Field label="Value" htmlFor="value"><Input id="value" name="value" required /></Field>
                <Field label="Category" htmlFor="threatCategory"><Select id="threatCategory" name="threatCategory">{ThreatCategorySchema.options.map((c) => <option key={c}>{c}</option>)}</Select></Field>
                <Field label="Confidence (0-100)" htmlFor="confidence"><Input id="confidence" name="confidence" type="number" min={0} max={100} defaultValue={90} /></Field>
                <Field label="Severity" htmlFor="severity"><Select id="severity" name="severity" defaultValue="high">{['low', 'medium', 'high', 'critical'].map((s) => <option key={s}>{s}</option>)}</Select></Field>
              </ActionForm>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </>
  );
}
