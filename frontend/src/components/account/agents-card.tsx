'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { AlertTriangle, Bot, Loader2, ShieldCheck } from 'lucide-react'
import { useAgents, useRevokeAgent } from '@/hooks/useAgents'
import { formatFingerprint, shortFingerprint } from '@/lib/fingerprint'
import { checkAgentKey, savePin } from '@/lib/pins'
import { AgentSummary } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { CopyButton } from '@/components/copy-button'
import { ConfirmButton } from './confirm-button'
import { useDateFormat } from './format'

export function AgentInitHint({ command = 'pastevault agent init' }: { command?: string }) {
  return (
    <div className="flex items-center gap-2 rounded-sm border border-border/80 bg-muted/40 py-1 pl-3 pr-1">
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">{command}</code>
      <CopyButton value={command} variant="ghost" size="sm" />
    </div>
  )
}

function AgentRow({ agent, userId, onError }: { agent: AgentSummary; userId: string; onError: (message: string) => void }) {
  const t = useTranslations('account.agents')
  const { dateTime, relative } = useDateFormat()
  const revokeAgent = useRevokeAgent()
  // Bumped after trusting a new key, to re-read the pin.
  const [, setPinVersion] = useState(0)
  const revoked = Boolean(agent.revoked_at)
  const check = checkAgentKey(userId, agent)
  const fingerprint = check.fingerprint

  return (
    <li
      className="space-y-2 rounded-sm border border-border/70 bg-background/55 p-3 data-[revoked=true]:opacity-60"
      data-revoked={revoked}
      data-testid="agent-row"
      data-agent={agent.name}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2">
            <Bot className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
            <span className="break-all font-mono text-sm font-semibold">{agent.name}</span>
            {revoked ? (
              <span className="meta-chip py-0.5">{t('revoked')}</span>
            ) : check.state === 'pinned' ? (
              <span className="meta-chip py-0.5 text-emerald-700 dark:text-emerald-300" title={t('pinnedHint')}>
                <ShieldCheck className="h-3 w-3" />
                {t('pinned')}
              </span>
            ) : null}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {revoked && agent.revoked_at
              ? t('revokedAt', { time: dateTime(agent.revoked_at) })
              : agent.last_used_at
                ? t('lastUsed', { time: relative(agent.last_used_at) })
                : t('neverUsed')}
          </p>
        </div>
        {!revoked && (
          <ConfirmButton
            label={t('revoke')}
            confirmLabel={t('confirmRevoke')}
            busy={revokeAgent.isPending}
            onConfirm={async () => {
              try {
                await revokeAgent.mutateAsync(agent.id)
              } catch (error) {
                onError((error as Error).message || t('revokeFailed'))
              }
            }}
          />
        )}
      </div>

      {fingerprint ? (
        <div className="flex items-center gap-1">
          <code
            className="min-w-0 flex-1 truncate font-mono text-xs text-foreground"
            title={formatFingerprint(fingerprint)}
            data-testid="agent-fingerprint"
          >
            {shortFingerprint(fingerprint)}…
          </code>
          <CopyButton value={fingerprint} variant="ghost" size="sm" label={t('copyFingerprint')} />
        </div>
      ) : null}

      {!revoked && check.state === 'mismatch' && (
        <div className="space-y-2 rounded-sm border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-800 dark:text-red-200" role="alert">
          <p className="flex items-start gap-1.5 font-medium">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            {t('mismatchTitle')}
          </p>
          <p>
            {t('mismatchBody', {
              pinned: shortFingerprint(check.pinnedFingerprint),
              name: agent.name,
            })}
          </p>
          <p className="break-all font-mono">{formatFingerprint(check.fingerprint)}</p>
          <ConfirmButton
            label={t('trustNewKey')}
            confirmLabel={t('confirmTrust')}
            onConfirm={() => {
              savePin(userId, agent, check.fingerprint, 'manual')
              setPinVersion((version) => version + 1)
            }}
          />
        </div>
      )}
      {!revoked && check.state === 'invalid' && (
        <p className="flex items-start gap-1.5 rounded-sm border border-red-500/30 bg-red-500/10 p-2.5 text-xs text-red-800 dark:text-red-200" role="alert">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {t('invalidKey')}
        </p>
      )}
    </li>
  )
}

export function AgentsCard({ userId, onError }: { userId: string; onError: (message: string) => void }) {
  const t = useTranslations('account.agents')
  const [showRevoked, setShowRevoked] = useState(false)
  const agentsQuery = useAgents({ includeRevoked: true })
  const agents = agentsQuery.data?.agents ?? []
  const active = agents.filter((agent) => !agent.revoked_at)
  const revoked = agents.filter((agent) => agent.revoked_at)
  const visible = showRevoked ? [...active, ...revoked] : active

  return (
    <Card data-testid="agents-card">
      <CardHeader>
        <CardTitle>{t('title')}</CardTitle>
        <CardDescription>{t('description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {agentsQuery.isLoading ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            {t('loading')}
          </p>
        ) : agentsQuery.isError ? (
          <p className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {(agentsQuery.error as Error).message || t('loadFailed')}
          </p>
        ) : active.length === 0 ? (
          <div className="space-y-2 text-sm text-muted-foreground" data-testid="agents-empty">
            <p>{t('empty')}</p>
            <AgentInitHint />
          </div>
        ) : null}

        {visible.length > 0 && (
          <ul className="space-y-2">
            {visible.map((agent) => (
              <AgentRow key={agent.id} agent={agent} userId={userId} onError={onError} />
            ))}
          </ul>
        )}

        {revoked.length > 0 && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="w-full"
            aria-pressed={showRevoked}
            onClick={() => setShowRevoked((value) => !value)}
          >
            {showRevoked ? t('hideRevoked') : t('showRevoked', { count: revoked.length })}
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
