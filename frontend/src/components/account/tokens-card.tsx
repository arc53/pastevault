'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { Bot, KeyRound, Loader2 } from 'lucide-react'
import { useApiTokens, useRevokeApiToken } from '@/hooks/useAccount'
import { ApiTokenSummary } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmButton } from './confirm-button'
import { NewTokenDialog, TOKEN_SCOPES } from './new-token-dialog'
import { useDateFormat } from './format'

// Active tokens shown before "Show all": keeps the side column compact.
const COLLAPSED_COUNT = 5

function isExpired(token: ApiTokenSummary) {
  return Boolean(token.expires_at && new Date(token.expires_at).getTime() <= Date.now())
}

function TokenRow({ token, onError }: { token: ApiTokenSummary; onError: (message: string) => void }) {
  const t = useTranslations('account.tokens')
  const { date, relative } = useDateFormat()
  const revokeToken = useRevokeApiToken()
  const inactive = Boolean(token.revoked_at) || isExpired(token)
  const allScopes = token.scopes.length === TOKEN_SCOPES.length

  return (
    <li
      className="space-y-2 rounded-sm border border-border/70 bg-background/55 p-3 data-[inactive=true]:opacity-60"
      data-inactive={inactive}
      data-testid="token-row"
      data-token-name={token.name}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="break-words text-sm font-semibold">{token.name}</p>
          <p className="mt-0.5 font-mono text-xs text-muted-foreground">{token.prefix}…</p>
        </div>
        {token.revoked_at ? (
          <span className="meta-chip py-0.5">{t('revoked')}</span>
        ) : isExpired(token) ? (
          <span className="meta-chip py-0.5">{t('expired')}</span>
        ) : (
          <ConfirmButton
            label={t('revoke')}
            confirmLabel={t('confirmRevoke')}
            busy={revokeToken.isPending}
            onConfirm={async () => {
              try {
                await revokeToken.mutateAsync(token.id)
              } catch (error) {
                onError((error as Error).message || t('revokeFailed'))
              }
            }}
          />
        )}
      </div>

      <div className="flex flex-wrap gap-1.5">
        {token.agent && (
          <span className="meta-chip py-0.5">
            <Bot className="h-3 w-3" />
            {token.agent.name}
          </span>
        )}
        <span className="meta-chip py-0.5" title={token.scopes.join(' ')}>
          {allScopes ? t('allScopes') : t('scopeCount', { count: token.scopes.length })}
        </span>
      </div>

      <p className="text-xs text-muted-foreground">
        {[
          token.revoked_at
            ? t('revokedOn', { date: date(token.revoked_at) })
            : token.expires_at
            ? isExpired(token)
              ? t('expiredOn', { date: date(token.expires_at) })
              : t('expiresOn', { date: date(token.expires_at) })
            : t('noExpiry'),
          token.last_used_at ? t('lastUsed', { time: relative(token.last_used_at) }) : t('neverUsed'),
        ].join(' · ')}
      </p>
    </li>
  )
}

export function TokensCard({ onError }: { onError: (message: string) => void }) {
  const t = useTranslations('account.tokens')
  const [showInactive, setShowInactive] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const tokensQuery = useApiTokens()
  const tokens = tokensQuery.data?.tokens ?? []
  const active = tokens.filter((token) => !token.revoked_at && !isExpired(token))
  const inactive = tokens.filter((token) => token.revoked_at || isExpired(token))
  const shownActive = showAll ? active : active.slice(0, COLLAPSED_COUNT)
  const hiddenActive = active.length - shownActive.length
  const visible = showInactive ? [...shownActive, ...inactive] : shownActive

  return (
    <Card data-testid="tokens-card">
      <CardHeader className="flex-row items-start justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <CardTitle>{t('title')}</CardTitle>
          <CardDescription>{t('description')}</CardDescription>
        </div>
        <NewTokenDialog />
      </CardHeader>
      <CardContent className="space-y-3">
        {tokensQuery.isLoading ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('loading')}
          </p>
        ) : tokensQuery.isError ? (
          <p className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {(tokensQuery.error as Error).message || t('loadFailed')}
          </p>
        ) : active.length === 0 ? (
          <p className="flex items-start gap-2 text-sm text-muted-foreground" data-testid="tokens-empty">
            <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
            {t('empty')}
          </p>
        ) : null}

        {visible.length > 0 && (
          <ul className="space-y-2">
            {visible.map((token) => (
              <TokenRow key={token.id} token={token} onError={onError} />
            ))}
          </ul>
        )}

        {hiddenActive > 0 && (
          <Button type="button" variant="ghost" size="sm" className="w-full" onClick={() => setShowAll(true)}>
            {t('showAll', { count: active.length })}
          </Button>
        )}

        {inactive.length > 0 && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="w-full"
            aria-pressed={showInactive}
            onClick={() => setShowInactive((value) => !value)}
          >
            {showInactive ? t('hideInactive') : t('showInactive', { count: inactive.length })}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
