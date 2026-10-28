'use client';
import { useState, useTransition } from 'react';
import type { ActionState } from '@/app/actions/state';
import { Button } from './ui/button';

/** Button that invokes a bound server action, optionally after confirmation. */
export function ActionButton({
  action,
  label,
  confirm,
  variant = 'outline',
  size = 'xs',
}: {
  action: () => Promise<ActionState>;
  label: string;
  confirm?: string;
  variant?: 'default' | 'outline' | 'danger' | 'ghost';
  size?: 'xs' | 'sm' | 'md';
}) {
  const [pending, start] = useTransition();
  const [result, setResult] = useState<ActionState | null>(null);
  return (
    <span className="inline-flex items-center gap-2">
      <Button
        type="button"
        variant={variant}
        size={size}
        disabled={pending}
        onClick={() => {
          if (confirm && !window.confirm(confirm)) return;
          start(async () => setResult(await action()));
        }}
      >
        {pending ? '…' : label}
      </Button>
      {result?.error ? <span role="alert" className="text-xs text-danger">{result.error}</span> : null}
      {result?.ok && result.message ? <span role="status" className="text-xs text-success">{result.message}</span> : null}
    </span>
  );
}
