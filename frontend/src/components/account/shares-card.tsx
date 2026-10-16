'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { useQueryClient } from '@tanstack/react-query'
import { Bot, ChevronDown, ExternalLink, Eye, KeyRound, Loader2, Lock, Trash2 } from 'lucide-react'
import { useAccountShares, useDeleteAccountShare } from '@/hooks/useAccount'
import { formatBytes } from '@/lib/file-shares'
import { shortFingerprint } from '@/lib/fingerprint'
import { cn } from '@/lib/utils'
import { AccountShare, OwnedShareStatus, OwnedShareType } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ConfirmButton } from './confirm-button'
import { ShareActivity } from './share-activity'
import { useDateFormat } from './format'

const STATUSES: OwnedShareStatus[] = ['active', 'uploading', 'burned', 'expired', 'deleted', 'abandoned']

function getShareHref(share: AccountShare) {
  return share.share_type === 'paste' ? `/p/${share.slug}` : `/f/${share.slug}`
}

// Legacy burn-after-read rows have no max_views but allow exactly one view.
function effectiveMaxViews(share: AccountShare) {
  return share.max_views ?? (share.burn_after_read ? 1 : null)
}

export function SharesCard({ onError }: { onError: (message: string) => void }) {
  const t = useTranslations('account.shares')
  const queryClient = useQueryClient()
  const deleteShare = useDeleteAccountShare()
  const { dateTime } = useDateFormat()
  const [statusFilter, setStatusFilter] = useState<'all' | OwnedShareStatus>('all')
  const [typeFilter, setTypeFilter] = useState<'all' | OwnedShareType>('all')
  const [expanded, setExpanded] = useState<string | null>(null)

  const sharesQuery = useAccountShares({
    share_type: typeFilter === 'all' ? undefined : typeFilter,
    status: statusFilter === 'all' ? undefined : statusFilter,
  })
  const shares = sharesQuery.data?.shares || []

  const activeCount = shares.filter((share) => share.status === 'active').length
  const totalViews = shares.reduce((total, share) => total + share.view_count, 0)

  const handleDeleteShare = async (shareId: string) => {
    try {
      await deleteShare.mutateAsync(shareId)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['account-shares'] }),
        queryClient.invalidateQueries({ queryKey: ['share-events', shareId] }),
        queryClient.invalidateQueries({ queryKey: ['audit'] }),
      ])
    } catch (error) {
      onError((error as Error).message || t('deleteFailed'))
    }
  }

  const describeShare = (share: AccountShare) => {
    if (share.share_type === 'paste') {
      return t('kindPaste')
    }
    const files = t('fileCount', { count: share.file_count || 0 })
    return share.total_size_bytes ? `${files} · ${formatBytes(Number(share.total_size_bytes))}` : files
  }

  return (
    <Card data-testid="shares-card">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="space-y-1">
          <CardTitle>{t('title')}</CardTitle>
          <CardDescription>{t('description')}</CardDescription>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Select value={typeFilter} onValueChange={(value) => setTypeFilter(value as 'all' | OwnedShareType)}>
            <SelectTrigger className="w-full sm:w-[140px]" aria-label={t('typeFilter')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('allTypes')}</SelectItem>
              <SelectItem value="paste">{t('pastes')}</SelectItem>
              <SelectItem value="file_share">{t('files')}</SelectItem>
            </SelectContent>
          </Select>
          <Select value={statusFilter} onValueChange={(value) => setStatusFilter(value as 'all' | OwnedShareStatus)}>
            <SelectTrigger className="w-full sm:w-[160px]" aria-label={t('statusFilter')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('allStatuses')}</SelectItem>
              {STATUSES.map((status) => (
                <SelectItem key={status} value={status}>
                  {t(`status.${status}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {sharesQuery.isLoading ? (
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('loading')}
          </div>
        ) : sharesQuery.isError ? (
          <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {sharesQuery.error instanceof Error ? sharesQuery.error.message : t('loadFailed')}
          </div>
        ) : shares.length === 0 ? (
          <div className="rounded-sm border border-border/70 bg-muted/25 p-4 text-sm text-muted-foreground">
            {t('empty')}
          </div>
        ) : (
          <>
          <p className="flex flex-wrap gap-2" data-testid="share-stats">
            <span className="meta-chip">
              {t('statTracked')} <strong>{shares.length}</strong>
            </span>
            <span className="meta-chip">
              {t('statActive')} <strong>{activeCount}</strong>
            </span>
            <span className="meta-chip">
              {t('statViews')} <strong>{totalViews}</strong>
            </span>
          </p>
          {shares.map((share) => {
            const maxViews = effectiveMaxViews(share)
            const sealed = Boolean(share.recipient_fingerprint)
            const isExpanded = expanded === share.id
            const activityId = `share-activity-${share.id}`

            return (
              <div
                key={share.id}
                className="rounded-sm border border-border/70 bg-background/55"
                data-testid="share-row"
                data-slug={share.slug}
              >
                <div className="flex flex-wrap items-start justify-between gap-3 p-4 pb-3">
                  <div className="min-w-0">
                    <p className="tool-label">{share.share_type === 'paste' ? t('kindPaste') : t('kindFiles')}</p>
                    <h2 className="break-all font-mono text-sm font-semibold">{share.slug}</h2>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {t(`status.${share.status}`)} · {describeShare(share)}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {share.is_password_protected || sealed ? (
                      <Button asChild variant="outline" size="sm">
                        <Link href={getShareHref(share)}>
                          <ExternalLink className="h-3.5 w-3.5" />
                          {t('open')}
                        </Link>
                      </Button>
                    ) : (
                      <span className="meta-chip">
                        <KeyRound className="h-3 w-3" />
                        {t('originalLinkRequired')}
                      </span>
                    )}
                    <ConfirmButton
                      label={
                        <>
                          <Trash2 className="h-3.5 w-3.5" />
                          {t('delete')}
                        </>
                      }
                      confirmLabel={t('confirmDelete')}
                      disabled={!share.can_delete}
                      busy={deleteShare.isPending && deleteShare.variables === share.id}
                      onConfirm={() => handleDeleteShare(share.id)}
                    />
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 px-4">
                  {sealed && (
                    <span
                      className="meta-chip border-primary/30 text-foreground"
                      title={share.recipient_fingerprint ?? undefined}
                      data-testid="sealed-badge"
                    >
                      <Bot className="h-3 w-3" />
                      {share.recipient_agent_name
                        ? t('sealedTo', { name: share.recipient_agent_name })
                        : t('sealedToKey', { fingerprint: shortFingerprint(share.recipient_fingerprint ?? '') })}
                    </span>
                  )}
                  {share.is_password_protected && (
                    <span className="meta-chip">
                      <Lock className="h-3 w-3" />
                      {t('passwordChip')}
                    </span>
                  )}
                </div>

                <dl className="grid grid-cols-2 gap-3 px-4 py-3 text-sm text-muted-foreground xl:grid-cols-4">
                  <div>
                    <dt className="tool-label">{t('created')}</dt>
                    <dd>{dateTime(share.created_at)}</dd>
                  </div>
                  <div>
                    <dt className="tool-label">{t('expires')}</dt>
                    <dd>{share.expires_at ? dateTime(share.expires_at) : t('never')}</dd>
                  </div>
                  <div>
                    <dt className="tool-label">{t('views')}</dt>
                    <dd className="inline-flex items-center gap-2 font-mono text-foreground" data-testid="share-views">
                      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                      {maxViews ? `${share.view_count}/${maxViews}` : share.view_count}
                    </dd>
                  </div>
                  <div>
                    <dt className="tool-label">{t('lastViewed')}</dt>
                    <dd>{share.last_viewed_at ? dateTime(share.last_viewed_at) : t('notViewed')}</dd>
                  </div>
                </dl>

                <div className="border-t border-border/60">
                  <button
                    type="button"
                    className="flex w-full items-center justify-between gap-2 px-4 py-2 text-left text-xs text-muted-foreground hover:bg-accent/30 hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring"
                    aria-expanded={isExpanded}
                    aria-controls={activityId}
                    onClick={() => setExpanded(isExpanded ? null : share.id)}
                  >
                    <span className="tool-label">{t('activity')}</span>
                    <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', isExpanded && 'rotate-180')} />
                  </button>
                  {isExpanded && (
                    <div id={activityId} className="px-4 pb-4 pt-1">
                      <ShareActivity shareId={share.id} />
                    </div>
                  )}
                </div>
              </div>
            )
          })}
          </>
        )}
      </CardContent>
    </Card>
  )
}
