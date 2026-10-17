'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ReactNode, useEffect, useMemo, useState } from 'react'
import { useTranslations } from 'next-intl'
import { useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock,
  KeyRound,
  Loader2,
  MessageSquareWarning,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react'
import { authClient } from '@/lib/auth-client'
import { ApiError, api, serverNow } from '@/lib/api'
import { formatFingerprint, shortFingerprint } from '@/lib/fingerprint'
import { checkAgentKey } from '@/lib/pins'
import { safeRedirectTarget, signInHref } from '@/lib/redirects'
import { cn } from '@/lib/utils'
import { formatBytes } from '@/lib/file-shares'
import { useGetCapabilities } from '@/hooks/usePaste'
import { useAgents } from '@/hooks/useAgents'
import { useSecretRequest } from '@/hooks/useSecretRequests'
import { SecretRequestDetails } from '@/types'
import { AccountLink } from '@/components/account-link'
import { Button } from '@/components/ui/button'
import { ConfirmButton } from '@/components/account/confirm-button'
import { AnswerForm } from '@/components/secret-request/answer-form'
import {
  checkRequestKey,
  formatCountdown,
  readLinkFingerprint,
  RequestKeyCheck,
} from '@/components/secret-request/key-check'

// The header shares the content column's width, so the title and the
// account link line up with the panels instead of the window edges.
const COLUMN = 'mx-auto w-full max-w-3xl'

function Shell({ title, label, children }: { title: ReactNode; label: string; children: ReactNode }) {
  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame py-3">
          <div className={cn(COLUMN, 'flex flex-wrap items-center justify-between gap-3')}>
            <div className="min-w-0">
              <p className="tool-label">{label}</p>
              <h1 className="break-all font-mono text-xl font-semibold sm:text-2xl">{title}</h1>
            </div>
            <AccountLink compact />
          </div>
        </div>
      </header>
      <div className="app-frame py-6 sm:py-8">
        <div className={cn(COLUMN, 'space-y-4')}>{children}</div>
      </div>
    </div>
  )
}

function Notice({
  tone,
  icon,
  title,
  children,
  testId,
}: {
  tone: 'ok' | 'warn' | 'error' | 'info'
  icon: ReactNode
  title: ReactNode
  children?: ReactNode
  testId?: string
}) {
  const tones = {
    ok: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-900 dark:text-emerald-100',
    warn: 'border-amber-500/35 bg-amber-500/10 text-amber-950 dark:text-amber-100',
    error: 'border-red-500/30 bg-red-500/10 text-red-900 dark:text-red-100',
    info: 'border-border/70 bg-muted/35 text-foreground',
  }
  return (
    <div
      className={cn('rounded-sm border p-3 text-sm', tones[tone])}
      role={tone === 'error' ? 'alert' : undefined}
      data-testid={testId}
    >
      <p className="flex items-start gap-2 font-medium">
        <span className="mt-0.5 shrink-0">{icon}</span>
        <span className="min-w-0">{title}</span>
      </p>
      {children && <div className="mt-1.5 space-y-1.5 pl-6 text-[13px] opacity-90">{children}</div>}
    </div>
  )
}

function Panel({ label, title, children }: { label: string; title?: ReactNode; children: ReactNode }) {
  return (
    <section className="tool-panel">
      <div className="tool-panel-header">
        <div className="min-w-0">
          <p className="tool-label">{label}</p>
          {title && <h2 className="break-all text-lg font-semibold">{title}</h2>}
        </div>
      </div>
      <div className="tool-panel-body space-y-4">{children}</div>
    </section>
  )
}

export default function SecretRequestPage() {
  const t = useTranslations('secretRequest')
  const params = useParams()
  const code = String(params?.code ?? '')
  const { data: capabilities, isPending } = useGetCapabilities()

  if (isPending) {
    return (
      <Shell title={code} label={t('label')}>
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('loading')}
        </p>
      </Shell>
    )
  }

  if (!capabilities?.auth?.enabled || !capabilities.features?.secret_requests) {
    return (
      <Shell title={code} label={t('label')}>
        <Notice tone="info" icon={<XCircle className="h-4 w-4" />} title={t('unavailable')} />
      </Shell>
    )
  }

  return <SignedInGate code={code} />
}

function SignedInGate({ code }: { code: string }) {
  const t = useTranslations('secretRequest')
  const { data: session, isPending } = authClient.useSession()
  const path = `/r/${encodeURIComponent(code)}`
  const [returnTo, setReturnTo] = useState(path)

  useEffect(() => {
    // Keep #fp= through the sign-in round trip; the account page only follows
    // same-origin paths (safeRedirectTarget).
    setReturnTo(safeRedirectTarget(`${path}${window.location.hash}`) ?? path)
  }, [path])

  if (isPending) {
    return (
      <Shell title={code} label={t('label')}>
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('loading')}
        </p>
      </Shell>
    )
  }

  if (!session) {
    return (
      <Shell title={code} label={t('label')}>
        <Panel label={t('label')} title={t('signInTitle')}>
          <p className="text-sm text-muted-foreground">{t('signInBody')}</p>
          <Button asChild>
            <Link href={signInHref(returnTo)} data-testid="sign-in-link">
              {t('signIn')}
            </Link>
          </Button>
        </Panel>
      </Shell>
    )
  }

  return <RequestView code={code} userId={session.user.id} />
}

// The server's "now" (Date header offset), ticking every second.
function useServerNow(active: boolean) {
  const [now, setNow] = useState(() => serverNow())
  useEffect(() => {
    if (!active) {
      return
    }
    setNow(serverNow())
    const id = window.setInterval(() => setNow(serverNow()), 1000)
    return () => window.clearInterval(id)
  }, [active])
  return now
}

function RequestView({ code, userId }: { code: string; userId: string }) {
  const t = useTranslations('secretRequest')
  const queryClient = useQueryClient()
  const requestQuery = useSecretRequest(code)
  const request = requestQuery.data
  // null until read; { value: undefined } when the link has no #fp=.
  const [linkFingerprint, setLinkFingerprint] = useState<{ value: string | undefined } | null>(null)
  const [sentHere, setSentHere] = useState(false)

  useEffect(() => {
    const read = () => setLinkFingerprint({ value: readLinkFingerprint() })
    read()
    window.addEventListener('hashchange', read)
    return () => window.removeEventListener('hashchange', read)
  }, [])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['secret-request', code] })

  if (requestQuery.isLoading || linkFingerprint === null) {
    return (
      <Shell title={code} label={t('label')}>
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('loading')}
        </p>
      </Shell>
    )
  }

  // The error view only replaces the page when there is nothing to show.
  // With a request on screen, a failed refresh is an inline notice and the
  // form keeps its state.
  if (!request) {
    const error = requestQuery.error
    const status = error instanceof ApiError ? error.status : 0
    return (
      <Shell title={code} label={t('label')}>
        <Notice
          tone={status === 404 ? 'info' : 'error'}
          icon={<XCircle className="h-4 w-4" />}
          title={status === 404 ? t('notFound') : status === 429 ? t('rateLimited') : t('loadFailed')}
          testId="request-error"
        >
          {status === 404 && <p>{t('notFoundBody')}</p>}
        </Notice>
        <Button asChild variant="outline" size="sm">
          <Link href="/account">{t('toAccount')}</Link>
        </Button>
      </Shell>
    )
  }

  return (
    <RequestDetails
      request={request}
      userId={userId}
      linkFingerprint={linkFingerprint.value}
      refreshFailed={requestQuery.isError}
      sentHere={sentHere}
      onSent={() => {
        setSentHere(true)
        void refresh()
      }}
      onChanged={() => void refresh()}
    />
  )
}

function RequestDetails({
  request,
  userId,
  linkFingerprint,
  refreshFailed,
  sentHere,
  onSent,
  onChanged,
}: {
  request: SecretRequestDetails
  userId: string
  linkFingerprint: string | undefined
  refreshFailed: boolean
  sentHere: boolean
  onSent: () => void
  onChanged: () => void
}) {
  const t = useTranslations('secretRequest')
  const pending = request.status === 'pending'
  const now = useServerNow(pending)
  const remaining = new Date(request.expires_at).getTime() - now
  // Only the server decides that a request expired; at zero the form is
  // disabled and the request re-read until the server says so.
  const expiring = pending && remaining <= 0
  const keyCheck: RequestKeyCheck = useMemo(
    () => checkRequestKey(request.public_key, request.fingerprint, linkFingerprint),
    [request.public_key, request.fingerprint, linkFingerprint]
  )
  const agentName = request.requester.agent.name ?? '?'

  useEffect(() => {
    if (!expiring) {
      return
    }
    onChanged()
    const id = window.setInterval(onChanged, 2_000)
    return () => window.clearInterval(id)
    // onChanged is stable in effect: it only invalidates this query.
  }, [expiring])

  return (
    <Shell title={request.name} label={t('labelWithCode', { code: request.code })}>
      {refreshFailed && (
        <p
          className="flex items-center gap-2 rounded-sm border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-xs text-amber-950 dark:text-amber-100"
          role="status"
          data-testid="refresh-failed"
        >
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
          {t('refreshFailed')}
        </p>
      )}
      <Panel label={t('fromLabel')}>
        <RequesterLine request={request} userId={userId} />

        {request.reason !== null && request.reason !== '' && (
          <div className="space-y-1.5">
            <p className="flex items-center gap-1.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
              <MessageSquareWarning className="h-3.5 w-3.5" />
              {t('reasonLabel')}
            </p>
            {/* Plain text only: React escapes it, and nothing here is parsed. */}
            <p
              className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-foreground [overflow-wrap:anywhere]"
              data-testid="request-reason"
            >
              {request.reason}
            </p>
          </div>
        )}

        <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="tool-label">{t('accepts')}</dt>
            <dd>{t(`accept.${request.accept}`)}</dd>
          </div>
          <div>
            <dt className="tool-label">{t('maxSize')}</dt>
            <dd>{formatBytes(request.max_bytes)}</dd>
          </div>
          {pending && (
            <div>
              <dt className="tool-label">{t('expiresIn')}</dt>
              <dd className="inline-flex items-center gap-1.5 font-mono tabular-nums" data-testid="countdown">
                <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                {formatCountdown(remaining)}
              </dd>
            </div>
          )}
        </dl>
      </Panel>

      {pending ? (
        <Panel label={t('answerLabel')} title={t('answerTitle', { name: request.name })}>
          {expiring && (
            <Notice tone="info" icon={<Clock className="h-4 w-4" />} title={t('expiring')} testId="state-expiring" />
          )}
          <KeyNotice check={keyCheck} code={request.code} />
          {keyCheck.state === 'verified' || keyCheck.state === 'unverified' ? (
            <AnswerForm
              request={request}
              requestPublicKey={keyCheck.publicKey}
              blocked={expiring}
              onSent={onSent}
              onDeclined={onChanged}
              onStale={onChanged}
            />
          ) : (
            <BlockedActions request={request} onChanged={onChanged} />
          )}
        </Panel>
      ) : (
        <Panel label={t('answerLabel')}>
          <FinalState request={request} agentName={agentName} sentHere={sentHere} />
        </Panel>
      )}
    </Shell>
  )
}

// With a blocked key only declining is offered.
function BlockedActions({ request, onChanged }: { request: SecretRequestDetails; onChanged: () => void }) {
  const t = useTranslations('secretRequest')
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <DeclineOnly requestId={request.id} onChanged={onChanged} />
      <Button type="button" disabled data-testid="submit-secret">
        {t('answer.send')}
      </Button>
    </div>
  )
}

function DeclineOnly({ requestId, onChanged }: { requestId: string; onChanged: () => void }) {
  const t = useTranslations('secretRequest.answer')
  const [busy, setBusy] = useState(false)
  return (
    <ConfirmButton
      busy={busy}
      label={t('decline')}
      confirmLabel={t('confirmDecline')}
      onConfirm={async () => {
        setBusy(true)
        try {
          await api.declineSecretRequest(requestId)
        } catch {
          // The refetch below shows whatever state the request is in.
        } finally {
          setBusy(false)
          onChanged()
        }
      }}
    />
  )
}

function KeyNotice({ check, code }: { check: RequestKeyCheck; code: string }) {
  const t = useTranslations('secretRequest.key')
  switch (check.state) {
    case 'verified':
      return (
        <Notice
          tone="ok"
          icon={<ShieldCheck className="h-4 w-4" />}
          title={t('verified')}
          testId="key-verified"
        >
          <p>{t('verifiedBody')}</p>
          <p className="break-all font-mono text-xs">{formatFingerprint(check.fingerprint)}</p>
        </Notice>
      )
    case 'unverified':
      return (
        <Notice
          tone="warn"
          icon={<AlertTriangle className="h-4 w-4" />}
          title={t('compareTitle', { short: shortFingerprint(check.fingerprint) })}
          testId="key-compare"
        >
          <p>{t('compareBody', { code })}</p>
          <p className="break-all font-mono text-xs">{formatFingerprint(check.fingerprint)}</p>
        </Notice>
      )
    case 'mismatch':
      return (
        <Notice
          tone="error"
          icon={<ShieldAlert className="h-4 w-4" />}
          title={t('mismatchTitle')}
          testId="key-mismatch"
        >
          <p>{t('mismatchBody')}</p>
          <p className="break-all font-mono text-xs">
            {t('linkSays')} {check.expected.slice(0, 80)}
          </p>
          <p className="break-all font-mono text-xs">
            {t('serverSays')} {formatFingerprint(check.fingerprint)}
          </p>
        </Notice>
      )
    default:
      return (
        <Notice tone="error" icon={<ShieldAlert className="h-4 w-4" />} title={t('invalidTitle')} testId="key-invalid">
          <p>{t('invalidBody')}</p>
        </Notice>
      )
  }
}

// The requesting agent, with this browser's pin of its identity key (the
// agent's own key, not the request key). Informational: the request key is
// what #fp= verifies.
function RequesterLine({ request, userId }: { request: SecretRequestDetails; userId: string }) {
  const t = useTranslations('secretRequest.requester')
  const agentsQuery = useAgents({ includeRevoked: true })
  const agent = agentsQuery.data?.agents.find((item) => item.id === request.requester.agent.id)
  const check = agent ? checkAgentKey(userId, agent) : null
  const name = request.requester.agent.name ?? '?'
  const identity = check?.fingerprint ?? request.requester.agent.fingerprint

  return (
    <div className="space-y-1" data-testid="requester">
      <p className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
        <Bot className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span>{t('agent')}</span>
        <span className="min-w-0 break-all font-mono font-semibold">{name}</span>
        {identity && <span className="font-mono text-xs text-muted-foreground">{shortFingerprint(identity)}…</span>}
        {check?.state === 'pinned' && (
          <span className="meta-chip py-0.5 text-emerald-700 dark:text-emerald-300">
            <ShieldCheck className="h-3 w-3" />
            {t('pinned')}
          </span>
        )}
        {check?.state === 'unpinned' && <span className="meta-chip py-0.5">{t('notPinned')}</span>}
        {(check?.state === 'mismatch' || check?.state === 'invalid') && (
          <span className="meta-chip border-amber-500/40 py-0.5 text-amber-700 dark:text-amber-300">
            <AlertTriangle className="h-3 w-3" />
            {t('pinMismatch')}
          </span>
        )}
        {agent?.revoked_at && <span className="meta-chip py-0.5">{t('revoked')}</span>}
      </p>
      {request.requester.token_name && (
        <p className="break-all pl-6 text-xs text-muted-foreground">
          <KeyRound className="mr-1 inline h-3 w-3" />
          {t('viaToken', { name: request.requester.token_name })}
        </p>
      )}
    </div>
  )
}

function FinalState({
  request,
  agentName,
  sentHere,
}: {
  request: SecretRequestDetails
  agentName: string
  sentHere: boolean
}) {
  const t = useTranslations('secretRequest.final')
  const status = request.status

  let content: ReactNode
  switch (status) {
    case 'fulfilled':
      content = (
        <Notice
          tone="info"
          icon={<Loader2 className="h-4 w-4 animate-spin" />}
          title={sentHere ? t('sentWaiting', { agent: agentName }) : t('answeredWaiting', { agent: agentName })}
          testId="state-fulfilled"
        >
          <p>{t('waitingBody')}</p>
        </Notice>
      )
      break
    case 'delivered':
      content = (
        <Notice
          tone="ok"
          icon={<CheckCircle2 className="h-4 w-4" />}
          title={t('delivered', { agent: agentName })}
          testId="state-delivered"
        >
          <p>{t('deliveredBody')}</p>
        </Notice>
      )
      break
    case 'declined':
      content = (
        <Notice tone="info" icon={<XCircle className="h-4 w-4" />} title={t('declined')} testId="state-declined">
          <p>{t('declinedBody', { agent: agentName })}</p>
        </Notice>
      )
      break
    case 'cancelled':
      content = (
        <Notice tone="info" icon={<XCircle className="h-4 w-4" />} title={t('cancelled', { agent: agentName })} testId="state-cancelled" />
      )
      break
    default:
      content = (
        <Notice tone="info" icon={<Clock className="h-4 w-4" />} title={t('expired')} testId="state-expired">
          <p>{t('expiredBody', { agent: agentName })}</p>
        </Notice>
      )
  }

  return (
    <div className="space-y-4" aria-live="polite">
      {content}
      <div className="flex justify-end">
        <Button asChild variant="outline" size="sm">
          <Link href="/account">{t('toAccount')}</Link>
        </Button>
      </div>
    </div>
  )
}
