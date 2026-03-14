import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded-sm border border-transparent text-[12px] font-medium tracking-[0.08em] transition-[background-color,border-color,color,box-shadow,transform] duration-150 ease-out focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-offset-0 disabled:pointer-events-none disabled:opacity-50 active:translate-y-px ring-offset-background',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.18),0_0_0_1px_rgba(15,23,42,0.08)] hover:bg-primary/92',
        destructive:
          'bg-destructive text-destructive-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.18)] hover:bg-destructive/90',
        outline:
          'border-input bg-background/70 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] hover:border-ring/40 hover:bg-accent/65 hover:text-accent-foreground',
        secondary:
          'border-border/70 bg-secondary/75 text-secondary-foreground hover:bg-secondary',
        ghost: 'hover:border-border/70 hover:bg-accent/45 hover:text-accent-foreground',
        link: 'underline-offset-4 hover:underline text-primary',
      },
      size: {
        default: 'h-9 px-3',
        sm: 'h-8 px-2.5 text-[11px]',
        lg: 'h-10 px-4 text-[12px]',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button'
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = 'Button'

export { Button, buttonVariants }
