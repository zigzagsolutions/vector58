import { cva, type VariantProps } from 'class-variance-authority';
import type { HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
  {
    variants: {
      tone: {
        neutral: 'bg-gray-100 text-gray-700',
        success: 'bg-green-50 text-green-800 ring-1 ring-green-200',
        warning: 'bg-amber-50 text-amber-800 ring-1 ring-amber-200',
        danger: 'bg-red-50 text-red-800 ring-1 ring-red-200',
        info: 'bg-blue-50 text-blue-800 ring-1 ring-blue-200',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export const Badge = ({
  className,
  tone,
  ...p
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) => (
  <span className={cn(badgeVariants({ tone }), className)} {...p} />
);
