'use client'

import { FormEvent, useState } from 'react'
import { useTranslations } from 'next-intl'
import { AlertTriangle, Plus } from 'lucide-react'
import { useCreateApiToken } from '@/hooks/useAccount'
import { useAgents } from '@/hooks/useAgents'
import { ApiScope, CreateApiTokenResponse } from '@/types'
import { Button } from '@/components/ui/button'
import { CopyButton } from '@/components/copy-button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

export const TOKEN_SCOPES: ApiScope[] = [
  'shares:create',
  'shares:read',
  'shares:revoke',
  'shares:receive',
  'agents:read',
  'agents:write',
  'requests:create',
  'audit:read',
]

// The server's default: everything except registering or revoking agents.
const DEFAULT_SCOPES = TOKEN_SCOPES.filter((scope) => scope !== 'agents:write')
const EXPIRY_OPTIONS = ['30', '90', '365', 'never'] as const
const NO_AGENT = 'none'

export function scopeMessageKey(scope: ApiScope) {
  return scope.replace(':', '_')
}

export function NewTokenDialog() {
  const t = useTranslations('account.tokens')
  const tCommon = useTranslations('common')
  const createToken = useCreateApiToken()
  const agentsQuery = useAgents()
  const agents = (agentsQuery.data?.agents ?? []).filter((agent) => !agent.revoked_at)

  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState<ApiScope[]>(DEFAULT_SCOPES)
  const [expiry, setExpiry] = useState<(typeof EXPIRY_OPTIONS)[number]>('90')
  const [agentId, setAgentId] = useState(NO_AGENT)
  const [error, setError] = useState('')
  const [created, setCreated] = useState<CreateApiTokenResponse | null>(null)

  const reset = () => {
    setName('')
    setScopes(DEFAULT_SCOPES)
    setExpiry('90')
    setAgentId(NO_AGENT)
    setError('')
    setCreated(null)
    createToken.reset()
  }

  // Every way of closing goes through here: the token is gone for good once
  // the dialog closes, and a reopened dialog always starts empty.
  const handleOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      reset()
    }
    setOpen(nextOpen)
  }

  // While a token is being created, or is on screen, the dialog only closes
  // through its own buttons: an Esc or a stray click outside must not lose a
  // token that is shown once (or create one the user never sees).
  const locked = createToken.isPending || created !== null
  const handleRadixOpenChange = (nextOpen: boolean) => {
    if (!nextOpen && locked) {
      return
    }
    handleOpenChange(nextOpen)
  }
  const preventWhileLocked = (event: Event) => {
    if (locked) {
      event.preventDefault()
    }
  }

  const toggleScope = (scope: ApiScope, checked: boolean) => {
    setScopes((current) =>
      checked ? TOKEN_SCOPES.filter((item) => item === scope || current.includes(item)) : current.filter((item) => item !== scope)
    )
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (!name.trim() || scopes.length === 0) {
      return
    }

    setError('')
    try {
      const response = await createToken.mutateAsync({
        name: name.trim(),
        scopes,
        expires_in_days: expiry === 'never' ? null : Number(expiry),
        ...(agentId !== NO_AGENT ? { agent_id: agentId } : {}),
      })
      setCreated(response)
    } catch (submitError) {
      setError((submitError as Error).message || t('createFailed'))
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleRadixOpenChange}>
      <DialogTrigger asChild>
        <Button type="button" size="sm" className="shrink-0 whitespace-nowrap" data-testid="new-token-button">
          <Plus className="h-3.5 w-3.5" />
          {t('newToken')}
        </Button>
      </DialogTrigger>
      <DialogContent
        closeLabel={tCommon('close')}
        hideClose={locked}
        onEscapeKeyDown={preventWhileLocked}
        onPointerDownOutside={preventWhileLocked}
        onInteractOutside={preventWhileLocked}
        data-testid="new-token-dialog"
      >
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>{t('createdTitle', { name: created.name })}</DialogTitle>
              <DialogDescription>{t('createdDescription')}</DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="space-y-2">
                <Label htmlFor="created-token">{t('tokenLabel')}</Label>
                <textarea
                  id="created-token"
                  readOnly
                  rows={2}
                  value={created.token}
                  onFocus={(event) => event.currentTarget.select()}
                  className="w-full resize-none break-all rounded-sm border border-border/80 bg-muted/40 p-3 font-mono text-xs text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  data-testid="created-token"
                />
                <CopyButton value={created.token} variant="outline" size="sm" />
              </div>
              <p className="flex items-start gap-2 rounded-sm border border-amber-500/25 bg-amber-500/10 p-3 text-xs">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-500" />
                <span>{t('shownOnce')}</span>
              </p>
              <div className="space-y-1 text-xs text-muted-foreground">
                <p>{t('useHint')}</p>
                <code className="block rounded-sm border border-border/80 bg-muted/40 px-3 py-2 font-mono text-foreground">
                  pastevault login --with-token
                </code>
              </div>
            </DialogBody>
            <DialogFooter>
              <Button type="button" onClick={() => handleOpenChange(false)}>
                {t('done')}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={(event) => void handleSubmit(event)} className="flex min-h-0 flex-1 flex-col">
            <DialogHeader>
              <DialogTitle>{t('dialogTitle')}</DialogTitle>
              <DialogDescription>{t('dialogDescription')}</DialogDescription>
            </DialogHeader>
            <DialogBody>
              <div className="space-y-2">
                <Label htmlFor="token-name">{t('nameLabel')}</Label>
                <Input
                  id="token-name"
                  value={name}
                  maxLength={64}
                  autoFocus
                  autoComplete="off"
                  placeholder={t('namePlaceholder')}
                  onChange={(event) => setName(event.target.value)}
                />
              </div>

              <fieldset className="space-y-2">
                <legend className="mb-2 text-[10px] font-medium uppercase tracking-[0.24em] text-muted-foreground">
                  {t('scopesLabel')}
                </legend>
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {TOKEN_SCOPES.map((scope) => (
                    <label
                      key={scope}
                      className="flex cursor-pointer items-start gap-2 rounded-sm border border-border/70 bg-muted/25 px-2.5 py-2 text-xs has-[:focus-visible]:ring-1 has-[:focus-visible]:ring-ring"
                    >
                      <input
                        type="checkbox"
                        className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[hsl(var(--primary))]"
                        checked={scopes.includes(scope)}
                        onChange={(event) => toggleScope(scope, event.target.checked)}
                        data-scope={scope}
                      />
                      <span className="min-w-0">
                        <span className="block font-mono text-foreground">{scope}</span>
                        <span className="block text-muted-foreground">{t(`scopes.${scopeMessageKey(scope)}`)}</span>
                      </span>
                    </label>
                  ))}
                </div>
                {scopes.length === 0 && <p className="text-xs text-red-700 dark:text-red-300">{t('scopesRequired')}</p>}
              </fieldset>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="token-expiry">{t('expiryLabel')}</Label>
                  <Select value={expiry} onValueChange={(value) => setExpiry(value as typeof expiry)}>
                    <SelectTrigger id="token-expiry">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {EXPIRY_OPTIONS.map((option) => (
                        <SelectItem key={option} value={option}>
                          {option === 'never' ? t('expiryNever') : t('expiryDays', { count: Number(option) })}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="token-agent">{t('agentLabel')}</Label>
                  <Select value={agentId} onValueChange={setAgentId} disabled={agents.length === 0}>
                    <SelectTrigger id="token-agent">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NO_AGENT}>{t('agentNone')}</SelectItem>
                      {agents.map((agent) => (
                        <SelectItem key={agent.id} value={agent.id}>
                          {agent.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                {agentId === NO_AGENT ? t('agentNoneHint') : t('agentBoundHint')}
              </p>

              {error && (
                <p className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200" role="alert">
                  {error}
                </p>
              )}
            </DialogBody>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={createToken.isPending}
                onClick={() => handleOpenChange(false)}
              >
                {tCommon('cancel')}
              </Button>
              <Button type="submit" disabled={!name.trim() || scopes.length === 0 || createToken.isPending}>
                {createToken.isPending ? t('creating') : t('create')}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
