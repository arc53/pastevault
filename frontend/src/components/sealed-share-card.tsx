'use client'

import Link from 'next/link'
import { useTranslations } from 'next-intl'
import { KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { CopyButton } from '@/components/copy-button'
import { formatFingerprint, isFingerprint, shortFingerprint } from '@/lib/fingerprint'

interface SealedShareCardProps {
  slug: string
  kind: 'paste' | 'file_share'
  fingerprint: string
  requiresRecipientAuth: boolean
}

// Shown instead of the viewer when a share is sealed to an agent key: the
// link has no #k= key, so a browser can't decrypt it. It only uses the
// non-consuming /meta response and never opens (or burns) the share.
export function SealedShareCard({ slug, kind, fingerprint, requiresRecipientAuth }: SealedShareCardProps) {
  const t = useTranslations('sealedShare')

  // The fingerprint comes from the server; it is only displayed here.
  const displayFingerprint = isFingerprint(fingerprint) ? fingerprint : ''
  const origin = typeof window === 'undefined' ? '' : window.location.origin
  const shareUrl = `${origin}/${kind === 'paste' ? 'p' : 'f'}/${slug}`
  const command = `pastevault get ${shareUrl}`

  return (
    <div className="app-frame py-8">
      <div className="mx-auto max-w-2xl tool-panel" data-testid="sealed-share-card">
        <div className="tool-panel-header">
          <div className="min-w-0">
            <p className="tool-label">{slug}</p>
            <h1 className="text-lg font-semibold break-words">
              {t('title', { fingerprint: shortFingerprint(displayFingerprint) || '?' })}
            </h1>
          </div>
          <span className="meta-chip">
            <KeyRound className="h-3.5 w-3.5" />
          </span>
        </div>
        <div className="tool-panel-body space-y-4 text-sm">
          <p className="text-muted-foreground">{t('description')}</p>

          <div className="space-y-1">
            <p className="tool-label">{t('fingerprintLabel')}</p>
            <p className="font-mono text-foreground break-words" data-testid="sealed-share-fingerprint">
              {displayFingerprint ? formatFingerprint(displayFingerprint) : '—'}
            </p>
          </div>

          <div className="space-y-2">
            <p className="tool-label">{t('commandLabel')}</p>
            <pre className="whitespace-pre-wrap break-all rounded-sm border border-border/80 bg-muted/40 p-3 font-mono text-xs text-foreground">
              <code data-testid="sealed-share-command">{command}</code>
            </pre>
            <CopyButton value={command} variant="outline" size="sm" label={t('copyCommand')} />
          </div>

          {requiresRecipientAuth && (
            <p className="text-muted-foreground">{t('accountNote')}</p>
          )}
          <p className="text-muted-foreground">{t('notOpened')}</p>

          <Link href="/" className="inline-block">
            <Button size="sm">{t('createNew')}</Button>
          </Link>
        </div>
      </div>
    </div>
  )
}
