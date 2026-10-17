'use client'

import { useTranslations } from 'next-intl'
import { Loader2 } from 'lucide-react'
import { useShareEvents } from '@/hooks/useAccount'
import { cn } from '@/lib/utils'
import { useAuditEventText, useDateFormat } from './format'

const EVENT_TONES: Record<string, string> = {
  'share.created': 'bg-primary',
  'share.viewed': 'bg-sky-500',
  'share.download_granted': 'bg-sky-500',
  'share.burned': 'bg-orange-500',
  'share.access_denied': 'bg-red-500',
  'share.revoked': 'bg-muted-foreground',
  'share.expired': 'bg-muted-foreground',
}

// Activity timeline of one tracked share (oldest first), loaded on expand.
export function ShareActivity({ shareId }: { shareId: string }) {
  const t = useTranslations('account.shares')
  const describe = useAuditEventText()
  const { dateTime, relative } = useDateFormat()
  const eventsQuery = useShareEvents(shareId)

  if (eventsQuery.isLoading) {
    return (
      <p className="flex items-center gap-2 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        {t('activityLoading')}
      </p>
    )
  }

  if (eventsQuery.isError) {
    return <p className="text-xs text-red-700 dark:text-red-300">{t('activityError')}</p>
  }

  const events = eventsQuery.data?.events ?? []
  if (events.length === 0) {
    return <p className="text-xs text-muted-foreground">{t('activityEmpty')}</p>
  }

  return (
    <ol className="space-y-3 border-l border-border/80 pl-4" data-testid="share-activity">
      {events.map((event) => {
        const text = describe(event)
        return (
          <li key={event.id} className="relative">
            <span
              aria-hidden="true"
              className={cn(
                'absolute -left-[21px] top-1.5 h-2 w-2 rounded-full ring-2 ring-background',
                EVENT_TONES[event.event] ?? 'bg-muted-foreground'
              )}
            />
            <p className="text-sm">
              <span className="font-medium text-foreground">{text.label}</span>
              {text.detail && <span className="text-muted-foreground"> · {text.detail}</span>}
            </p>
            <p className="text-xs text-muted-foreground">
              {[text.actor, text.client].filter(Boolean).join(' · ')} ·{' '}
              <time dateTime={event.created_at} title={dateTime(event.created_at)}>
                {relative(event.created_at)}
              </time>
            </p>
          </li>
        )
      })}
    </ol>
  )
}
