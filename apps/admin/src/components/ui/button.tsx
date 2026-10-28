import { cva, type VariantProps } from 'class-variance-authority';
import type { ButtonHTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-blue-800',
        outline: 'border border-border bg-surface hover:bg-gray-50',
        ghost: 'hover:bg-gray-100',
        danger: 'bg-danger text-white hover:bg-red-800',
        link: 'text-primary underline-offset-2 hover:underline px-0',
      },
      size: { sm: 'h-8 px-3', md: 'h-9 px-4', xs: 'h-7 px-2 text-xs' },
    },
    defaultVariants: { variant: 'default', size: 'md' },
  },
);

export function Button({
  className,
  variant,
  size,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>) {
  return <button className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
