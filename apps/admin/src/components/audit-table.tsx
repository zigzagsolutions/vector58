import { EmptyState } from './page';
import { Table, TBody, TD, TH, THead, TR } from './ui/table';
import { formatDateTime } from '@/lib/utils';
import type { AuditRow } from '@/server/services/audit-log';

export function AuditTable({ rows, showTenant }: { rows: AuditRow[]; showTenant?: boolean }) {
  if (rows.length === 0) return <EmptyState title="No audit entries" />;
  return (
    <Table>
      <THead>
        <TR>
          <TH>Time</TH>
          {showTenant ? <TH>Tenant</TH> : null}
          <TH>Action</TH>
          <TH>Actor</TH>
          <TH>Scope / role</TH>
          <TH>Target</TH>
          <TH>Details</TH>
        </TR>
      </THead>
      <TBody>
        {rows.map((a) => (
          <TR key={a.id}>
            <TD className="whitespace-nowrap text-xs">{formatDateTime(a.occurredAt)}</TD>
            {showTenant ? <TD>{a.organizationName ?? 'Platform'}</TD> : null}
            <TD className="font-mono text-xs">{a.action}</TD>
            <TD>
              {a.actorEmail ??
                (a.actorDeviceId ? `device ${a.actorDeviceId.slice(0, 8)}` : a.actorScope)}
            </TD>
            <TD className="text-xs">
              {a.actorScope}
              {a.platformRole ? <div className="text-muted">platform: {a.platformRole}</div> : null}
              {a.tenantRole ? <div className="text-muted">tenant: {a.tenantRole}</div> : null}
              {a.tenantContextId ? <div className="text-amber-700">via tenant context</div> : null}
            </TD>
            <TD className="text-xs">
              {a.targetType}
              {a.targetId ? (
                <div className="font-mono text-[11px] text-muted">{a.targetId}</div>
              ) : null}
            </TD>
            <TD
              className="max-w-sm truncate font-mono text-[11px] text-muted"
              title={JSON.stringify(a.metadata)}
            >
              {JSON.stringify(a.metadata)}
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
