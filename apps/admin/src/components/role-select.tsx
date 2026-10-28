'use client';
import { useState, useTransition } from 'react';
import { changeRoleAction } from '@/app/actions/tenant';
import { Select } from './ui/form';

export function RoleSelect({
  orgId,
  userId,
  current,
  roles,
}: {
  orgId: string;
  userId: string;
  current: string;
  roles: { key: string; name: string }[];
}) {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const options = roles.some((r) => r.key === current)
    ? roles
    : [{ key: current, name: current }, ...roles];
  return (
    <span className="inline-flex items-center gap-2">
      <Select
        aria-label="Role"
        className="h-8 w-48"
        defaultValue={current}
        disabled={pending}
        onChange={(e) =>
          start(async () => {
            const r = await changeRoleAction(orgId, userId, e.target.value);
            setError(r.ok ? null : (r.error ?? 'Failed'));
          })
        }
      >
        {options.map((r) => (
          <option key={r.key} value={r.key}>
            {r.name}
          </option>
        ))}
      </Select>
      {error ? (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      ) : null}
    </span>
  );
}
