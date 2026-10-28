'use client';
import { useTransition } from 'react';
import { exitTenantAction } from '@/app/actions/platform';
import { Button } from './ui/button';

export function ExitTenantButton() {
  const [pending, start] = useTransition();
  return (
    <Button
      size="sm"
      variant="outline"
      disabled={pending}
      onClick={() => start(() => exitTenantAction())}
    >
      Return to Platform
    </Button>
  );
}
