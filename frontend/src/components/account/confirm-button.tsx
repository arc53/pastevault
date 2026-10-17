'use client'

import { ReactNode, useEffect, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Button } from '@/components/ui/button'

interface ConfirmButtonProps {
  label: ReactNode
  confirmLabel: string
  onConfirm: () => void | Promise<void>
  disabled?: boolean
  busy?: boolean
  // Accessible name for the first button when `label` is only an icon.
  ariaLabel?: string
}

// A destructive action that takes two clicks: the first swaps the button for
// "Confirm" / "Cancel" inline, so no modal is needed for a single row.
export function ConfirmButton({ label, confirmLabel, onConfirm, disabled, busy, ariaLabel }: ConfirmButtonProps) {
  const t = useTranslations('common')
  const [confirming, setConfirming] = useState(false)
  const confirmRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (confirming) {
      confirmRef.current?.focus()
    }
  }, [confirming])

  if (!confirming) {
    return (
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={disabled || busy}
        aria-label={ariaLabel}
        onClick={() => setConfirming(true)}
      >
        {label}
      </Button>
    )
  }

  return (
    <span className="inline-flex gap-1.5">
      <Button
        ref={confirmRef}
        type="button"
        variant="destructive"
        size="sm"
        disabled={busy}
        onClick={async () => {
          try {
            await onConfirm()
          } finally {
            setConfirming(false)
          }
        }}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            setConfirming(false)
          }
        }}
      >
        {confirmLabel}
      </Button>
      <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setConfirming(false)}>
        {t('cancel')}
      </Button>
    </span>
  )
}
