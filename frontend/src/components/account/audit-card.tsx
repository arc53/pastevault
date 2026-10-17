'use client'

import Link from 'next/link'
import { useTranslations } from 'next-intl'
import { Loader2 } from 'lucide-react'
import { useAuditLog } from '@/hooks/useAccount'
import { AuditEvent } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useAuditEventText, useDateFormat } from './format'

function subjectHref(event: AuditEvent) {
  if (!event.slug) {
    return null
  }
  if (event.subject_type === 'paste') {
    return `/p/${event.slug}`
  }
  if (event.subject_type === 'file_share') {
    return `/f/${event.slug}`
  }
  return null
}

// The account's audit log, newest first, paged with the server's cursor.
export function AuditCard() {
  const t = useTranslations('account.audit')
  const describe = useAuditEventText()
  const { dateTime, relative } = useDateFormat()
  const auditQuery = useAuditLog()
  const events = auditQuery.data?.pages.flatMap((page) => page.events) ?? []

  return (
    <Card data-testid="audit-card">
      <CardHeader>
        <CardTitle>{t('title')}</CardTitle>
        <CardDescription>{t('description')}</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        {auditQuery.isLoading ? (
          <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('loading')}
          </p>
        ) : auditQuery.isError ? (
          <p className="m-4 rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {(auditQuery.error as Error).message || t('loadFailed')}
          </p>
        ) : events.length === 0 ? (
          <p className="p-4 text-sm text-muted-foreground">{t('empty')}</p>
        ) : (
          <ul className="divide-y divide-border/60" data-testid="audit-list">
            {events.map((event) => {
              const text = describe(event)
              const href = subjectHref(event)
              return (
                <li key={event.id} className="grid gap-1 px-4 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-4" data-testid="audit-row">
                  <div className="min-w-0">
                    <p className="text-sm">
                      <span className="font-medium text-foreground">{text.label}</span>
                      {event.slug &&
                        (href ? (
                          <Link href={href} className="ml-2 font-mono text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline">
                            {event.slug}
                          </Link>
                        ) : (
                          <span className="ml-2 font-mono text-xs text-muted-foreground">{event.slug}</span>
                        ))}
                      {text.detail && <span className="text-muted-foreground"> · {text.detail}</span>}
                    </p>
                    <p className="truncate text-xs text-muted-foreground">
                      {[text.actor, text.client].filter(Boolean).join(' · ')}
                    </p>
                  </div>
                  <time
                    dateTime={event.created_at}
                    title={dateTime(event.created_at)}
                    className="whitespace-nowrap text-xs text-muted-foreground sm:text-right"
                  >
                    {relative(event.created_at)}
                  </time>
                </li>
              )
            })}
          </ul>
        )}
        {auditQuery.hasNextPage && (
          <div className="border-t border-border/60 p-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-full"
              disabled={auditQuery.isFetchingNextPage}
              onClick={() => void auditQuery.fetchNextPage()}
              data-testid="audit-load-more"
            >
              {auditQuery.isFetchingNextPage ? t('loadingMore') : t('loadMore')}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
