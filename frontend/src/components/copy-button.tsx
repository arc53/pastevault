'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Copy, Check } from 'lucide-react'
import { cn } from '@/lib/utils'

type ButtonProps = React.ComponentProps<typeof Button>

interface CopyButtonProps extends Omit<ButtonProps, 'onClick' | 'children'> {
  value?: string
  getValue?: () => string
  label?: string
  copiedLabel?: string
  successDurationMs?: number
  withIcon?: boolean
}

export function CopyButton({
  value,
  getValue,
  label = 'Copy',
  copiedLabel = 'Copied!',
  successDurationMs = 1500,
  withIcon = true,
  className,
  ...buttonProps
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const reserveLabel = label.length >= copiedLabel.length ? label : copiedLabel

  const handleClick = async () => {
    try {
      const text = (typeof getValue === 'function' ? getValue() : value) ?? ''
      if (!text) return
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), successDurationMs)
    } catch {
      // no-op (clipboard may be unavailable)
    }
  }

  return (
    <Button
      type="button"
      onClick={handleClick}
      aria-live="polite"
      aria-label={copied ? copiedLabel : label}
      className={cn(
        'transition-colors',
        copied && 'bg-green-600 text-white border-green-600 hover:bg-green-600 animate-pulse',
        className
      )}
      {...buttonProps}
    >
      {withIcon && (
        copied ? (
          <Check className="h-4 w-4 mr-1" />
        ) : (
          <Copy className="h-4 w-4 mr-1" />
        )
      )}
      <span className="relative inline-block whitespace-nowrap">
        <span className="invisible">{reserveLabel}</span>
        <span className="absolute inset-0">{copied ? copiedLabel : label}</span>
      </span>
    </Button>
  )
}
