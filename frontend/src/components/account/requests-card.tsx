'use client'

import Link from 'next/link'
import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { Bot, KeyRound, Loader2 } from 'lucide-react'
import { useSecretRequests } from '@/hooks/useSecretRequests'
import { cn } from '@/lib/utils'
import { SecretRequestStatus, SecretRequestSummary } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AgentInitHint } from './agents-card'
import { useDateFormat } from './format'

const RECENT_COUNT = 5

const STATUS_TONES: Record<SecretRequestStatus, string> = {
  pending: 'border-amber-500/40 text-amber-700 dark:text-amber-300',
  fulfilled: 'border-sky-500/40 text-sky-700 dark:text-sky-300',
  delivered: 'border-emerald-500/40 text-emerald-700 dark:text-emerald-300',
  declined: '',
  expired: '',
  cancelled: '',
}

function isOpen(request: SecretRequestSummary) {
  return request.status === 'pending' && new Date(request.expires_at).getTime() > Date.now()
}

function RequestRow({ request }: { request: SecretRequestSummary }) {
  const t = useTranslations('account.requests')
  const { dateTime, relative } = useDateFormat()
  const open = isOpen(request)
  // A pending request past its expiry is settled lazily by the server.
  const status: SecretRequestStatus = request.status === 'pending' && !open ? 'expired' : request.status

  return (
    <li
      className="flex flex-wrap items-start justify-between gap-3 px-4 py-3"
      data-testid="request-row"
      data-code={request.code}
      data-status={status}
    >
      <div className="min-w-0 space-y-1">
        <p className="flex flex-wrap items-center gap-2">
          <KeyRound className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <span className="break-all font-mono text-sm font-semibold">{request.name}</span>
          <span className={cn('meta-chip py-0.5', STATUS_TONES[status])}>{t(`status.${status}`)}</span>
        </p>
        <p className="text-xs text-muted-foreground">
          <Bot className="mr-1 inline h-3 w-3" />
          {[
            request.requester.agent.name ?? '?',
            request.code,
            t('created', { time: relative(request.created_at) }),
            open ? t('expires', { time: relative(request.expires_at) }) : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        </p>
      </div>
      {open && (
        <Button asChild size="sm" variant="outline" title={dateTime(request.expires_at)}>
          <Link href={`/r/${request.code}`}>{t('answer')}</Link>
        </Button>
      )}
    </li>
  )
}

// Secret requests made by the account's agents: metadata only. Pending ones
// link to /r/<code>; without #fp= that page asks to compare the key by eye.
export function RequestsCard() {
  const t = useTranslations('account.requests')
  const [showAll, setShowAll] = useState(false)
  const requestsQuery = useSecretRequests()
  const requests = requestsQuery.data?.requests ?? []
  const pending = requests.filter(isOpen)
  const recent = requests.filter((request) => !isOpen(request))
  const visibleRecent = showAll ? recent : recent.slice(0, RECENT_COUNT)

  return (
    <Card data-testid="requests-card">
      <CardHeader>
        <CardTitle>{t('title')}</CardTitle>
        <CardDescription>{t('description')}</CardDescription>
      </CardHeader>
      <CardContent className="p-0">
        {requestsQuery.isLoading ? (
          <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('loading')}
          </p>
        ) : requestsQuery.isError ? (
          <p className="m-4 rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {(requestsQuery.error as Error).message || t('loadFailed')}
          </p>
        ) : requests.length === 0 ? (
          <div className="space-y-2 p-4 text-sm text-muted-foreground" data-testid="requests-empty">
            <p>{t('empty')}</p>
            <AgentInitHint command="pastevault request NAME" />
          </div>
        ) : (
          <>
            {pending.length > 0 && (
              <>
                <p className="tool-label px-4 pt-3">{t('pending', { count: pending.length })}</p>
                <ul className="divide-y divide-border/60">
                  {pending.map((request) => (
                    <RequestRow key={request.id} request={request} />
                  ))}
                </ul>
              </>
            )}
            {recent.length > 0 && (
              <>
                <p className={cn('tool-label px-4 pt-3', pending.length > 0 && 'border-t border-border/60')}>
                  {t('recent')}
                </p>
                <ul className="divide-y divide-border/60">
                  {visibleRecent.map((request) => (
                    <RequestRow key={request.id} request={request} />
                  ))}
                </ul>
              </>
            )}
            {recent.length > RECENT_COUNT && (
              <div className="border-t border-border/60 p-3">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="w-full"
                  aria-pressed={showAll}
                  onClick={() => setShowAll((value) => !value)}
                >
                  {showAll ? t('showLess') : t('showAll', { count: recent.length })}
                </Button>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}
