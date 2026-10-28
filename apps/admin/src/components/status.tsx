import type { ProtectionStatus } from '@bsp/policy-types';
import { Badge } from './ui/badge';

const PROTECTION: Record<ProtectionStatus, { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' | 'info' }> = {
  protected: { label: 'Protected', tone: 'success' },
  degraded: { label: 'Degraded', tone: 'warning' },
  policy_outdated: { label: 'Policy Outdated', tone: 'warning' },
  offline: { label: 'Offline', tone: 'danger' },
  never_enrolled: { label: 'Never Enrolled', tone: 'neutral' },
};

export const ProtectionBadge = ({ status }: { status: ProtectionStatus }) => (
  <Badge tone={PROTECTION[status].tone}>
    <span className="inline-block h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
    {PROTECTION[status].label}
  </Badge>
);

export function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  const tone =
    ['active', 'completed', 'published', 'succeeded', 'closed'].includes(s) ? 'success'
    : ['disabled', 'failed', 'revoked', 'expired', 'critical'].includes(s) ? 'danger'
    : ['pending', 'received', 'running', 'investigating', 'high', 'superseded', 'exhausted'].includes(s) ? 'warning'
    : 'neutral';
  return <Badge tone={tone}>{status}</Badge>;
}

export function CategoryBadge({ category }: { category: string | null }) {
  if (!category) return <span className="text-muted">—</span>;
  const tone = ['malware', 'command-and-control', 'malicious-download'].includes(category) ? 'danger' : category === 'custom' ? 'neutral' : 'warning';
  return <Badge tone={tone}>{category}</Badge>;
}
