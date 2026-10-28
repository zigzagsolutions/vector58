import Link from 'next/link';
import {
  Activity,
  Building2,
  Check,
  Gauge,
  List,
  LogOut,
  Monitor,
  Rss,
  ScrollText,
  Settings,
  Shield,
  ShieldCheck,
  Siren,
  Users,
  Zap,
} from 'lucide-react';
import type { ReactNode } from 'react';
import type { NavItem } from '@/lib/navigation';
import { ExitTenantButton } from './exit-tenant-button';

const ICONS: Record<string, typeof Gauge> = {
  gauge: Gauge,
  building: Building2,
  shield: Shield,
  rss: Rss,
  activity: Activity,
  scroll: ScrollText,
  settings: Settings,
  users: Users,
  monitor: Monitor,
  list: List,
  check: Check,
  zap: Zap,
  siren: Siren,
};

export interface ShellProps {
  readonly title: string;
  readonly subtitle: string;
  readonly nav: readonly NavItem<string>[];
  readonly userEmail: string | null;
  readonly tenantBanner?: { organizationName: string; expiresAt: string } | null;
  readonly switcher?: { href: string; label: string }[];
  readonly children: ReactNode;
}

export function Shell({
  title,
  subtitle,
  nav,
  userEmail,
  tenantBanner,
  switcher,
  children,
}: ShellProps) {
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col bg-sidebar text-sidebar-foreground">
        <div className="flex items-center gap-2 border-b border-white/10 px-4 py-4">
          <ShieldCheck className="h-5 w-5 text-blue-400" aria-hidden />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-white">{title}</p>
            <p className="truncate text-xs text-slate-400">{subtitle}</p>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-2" aria-label="Main">
          {nav.map((item) => {
            const Icon = ICONS[item.icon] ?? Gauge;
            return (
              <Link
                key={item.href}
                href={item.href}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-white/10 hover:text-white"
              >
                <Icon className="h-4 w-4" aria-hidden />
                {item.label}
              </Link>
            );
          })}
        </nav>
        {switcher && switcher.length > 0 ? (
          <div className="border-t border-white/10 p-2">
            <p className="px-3 pb-1 text-[11px] uppercase tracking-wide text-slate-500">Switch</p>
            {switcher.map((s) => (
              <Link
                key={s.href}
                href={s.href}
                className="block truncate rounded-md px-3 py-1.5 text-xs hover:bg-white/10"
              >
                {s.label}
              </Link>
            ))}
          </div>
        ) : null}
        <div className="border-t border-white/10 p-3 text-xs">
          <p className="truncate text-slate-300">{userEmail}</p>
          <form action="/auth/signout" method="post" className="mt-2">
            <button className="inline-flex items-center gap-1 text-slate-400 hover:text-white">
              <LogOut className="h-3.5 w-3.5" aria-hidden /> Sign out
            </button>
          </form>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        {tenantBanner ? (
          <div
            role="status"
            className="flex items-center justify-between gap-4 bg-amber-100 px-6 py-2 text-sm text-amber-900 ring-1 ring-amber-300"
          >
            <span>
              <strong>Viewing Tenant: {tenantBanner.organizationName}</strong>
              <span className="ml-2 text-amber-800">
                You are acting as yourself in a platform support context. All actions are audited.
                Context expires {new Date(tenantBanner.expiresAt).toUTCString()}.
              </span>
            </span>
            <ExitTenantButton />
          </div>
        ) : null}
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
