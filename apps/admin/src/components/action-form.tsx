'use client';
import { useActionState, type ReactNode } from 'react';
import type { ActionState } from '@/app/actions/state';
import { Button } from './ui/button';

/** Form bound to a server action; shows success/error feedback inline. */
export function ActionForm({
  action,
  submitLabel,
  children,
  className,
  renderResult,
}: {
  action: (prev: ActionState, form: FormData) => Promise<ActionState>;
  submitLabel: string;
  children: ReactNode;
  className?: string;
  renderResult?: (state: ActionState) => ReactNode;
}) {
  const [state, formAction, pending] = useActionState(action, { ok: false });
  return (
    <form action={formAction} className={className ?? 'space-y-3'}>
      {children}
      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>
          {pending ? 'Working…' : submitLabel}
        </Button>
        {state.error ? (
          <p role="alert" className="text-sm text-danger">
            {state.error}
          </p>
        ) : null}
        {state.ok && state.message ? (
          <p role="status" className="text-sm text-success">
            {state.message}
          </p>
        ) : null}
      </div>
      {state.ok && renderResult ? renderResult(state) : null}
    </form>
  );
}
