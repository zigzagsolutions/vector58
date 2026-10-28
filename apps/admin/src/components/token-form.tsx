'use client';
import type { ActionState } from '@/app/actions/state';
import { ActionForm } from './action-form';
import { Field, Input } from './ui/form';

export function TokenForm({ action }: { action: (prev: ActionState, form: FormData) => Promise<ActionState> }) {
  return (
    <ActionForm
      action={action}
      submitLabel="Create token"
      renderResult={(s) => (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs">
          <p className="mb-1 font-medium">Copy this token now. It is stored only as a hash and cannot be shown again.</p>
          <code className="block break-all font-mono">{String(s.data?.token ?? '')}</code>
          <p className="mt-2 text-muted">Install: <code>Install-Agent.ps1 -ApiBaseUrl &lt;url&gt; -EnrollmentToken &lt;token&gt;</code></p>
        </div>
      )}
    >
      <Field label="Description" htmlFor="description"><Input id="description" name="description" placeholder="e.g. Finance laptops" /></Field>
      <Field label="Maximum uses" htmlFor="maxUses"><Input id="maxUses" name="maxUses" type="number" min={1} defaultValue={25} /></Field>
      <Field label="Valid for (hours)" htmlFor="expiresInHours"><Input id="expiresInHours" name="expiresInHours" type="number" min={1} max={2160} defaultValue={72} /></Field>
    </ActionForm>
  );
}
