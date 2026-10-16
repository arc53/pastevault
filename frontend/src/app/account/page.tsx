'use client'

import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { useQueryClient } from '@tanstack/react-query'
import { Loader2, UserRound, X } from 'lucide-react'
import { authClient } from '@/lib/auth-client'
import { safeRedirectTarget } from '@/lib/redirects'
import { useGetCapabilities } from '@/hooks/usePaste'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { AgentsCard } from '@/components/account/agents-card'
import { AuditCard } from '@/components/account/audit-card'
import { AuthPanel } from '@/components/account/auth-panel'
import { RequestsCard } from '@/components/account/requests-card'
import { SharesCard } from '@/components/account/shares-card'
import { TokensCard } from '@/components/account/tokens-card'

function LoadingPanel({ label }: { label: string }) {
  return (
    <div className="app-frame py-10">
      <div className="tool-panel">
        <div className="tool-panel-body flex items-center gap-3 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          {label}
        </div>
      </div>
    </div>
  )
}

export default function AccountPage() {
  const t = useTranslations('account')
  const router = useRouter()
  const { data: capabilities, isPending } = useGetCapabilities()
  const authEnabled = capabilities?.auth?.enabled !== false

  useEffect(() => {
    if (!authEnabled) {
      router.replace('/')
    }
  }, [authEnabled, router])

  if (isPending) {
    return <LoadingPanel label={t('loadingConfig')} />
  }

  if (!authEnabled) {
    return null
  }

  const features = capabilities?.features
  return (
    <AccountContent
      signupEnabled={capabilities?.auth?.signup_enabled !== false}
      // Older servers (api_version 1) have neither agents, tokens nor audit.
      showAgents={Boolean(features?.agents)}
      showTokens={Boolean(features?.api_tokens)}
      showAudit={Boolean(features?.audit)}
      showRequests={Boolean(features?.secret_requests)}
    />
  )
}

function AccountContent({
  signupEnabled,
  showAgents,
  showTokens,
  showAudit,
  showRequests,
}: {
  signupEnabled: boolean
  showAgents: boolean
  showTokens: boolean
  showAudit: boolean
  showRequests: boolean
}) {
  const t = useTranslations('account')
  const router = useRouter()
  const searchParams = useSearchParams()
  const queryClient = useQueryClient()
  const { data: session, isPending: isSessionPending } = authClient.useSession()
  const redirectTarget = safeRedirectTarget(searchParams.get('redirectTo'))
  const [pageError, setPageError] = useState('')

  useEffect(() => {
    if (session && redirectTarget) {
      router.replace(redirectTarget)
    }
  }, [redirectTarget, router, session])

  const handleSignOut = async () => {
    setPageError('')

    try {
      await authClient.signOut()
      queryClient.clear()
    } catch (error) {
      setPageError((error as Error).message || t('signOutFailed'))
    }
  }

  if (isSessionPending) {
    return <LoadingPanel label={t('loadingAccount')} />
  }

  if (!session) {
    return (
      <AuthPanel
        signupEnabled={signupEnabled}
        onSignedIn={() => {
          if (redirectTarget) {
            router.push(redirectTarget)
          }
        }}
      />
    )
  }

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">{t('label')}</p>
            <h1 className="truncate text-xl font-semibold sm:text-2xl">
              {session.user.username || session.user.name || t('label')}
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link href="/">{t('backToEditor')}</Link>
            </Button>
            <Button variant="outline" onClick={() => void handleSignOut()}>
              {t('signOut')}
            </Button>
          </div>
        </div>
      </header>

      {pageError && (
        <div className="app-frame pt-4">
          <div
            className="flex items-start justify-between gap-3 rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200"
            role="alert"
          >
            <span>{pageError}</span>
            <button
              type="button"
              className="shrink-0 rounded-sm p-0.5 hover:bg-red-500/10 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              aria-label={t('dismiss')}
              onClick={() => setPageError('')}
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      <div className="app-frame grid gap-4 py-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="min-w-0 space-y-4">
          <SharesCard onError={setPageError} />
          {showRequests && <RequestsCard />}
          {showAudit && <AuditCard />}
        </section>

        <aside className="min-w-0 space-y-4">
          {showAgents && <AgentsCard userId={session.user.id} onError={setPageError} />}
          {showTokens && <TokensCard onError={setPageError} />}

          <Card>
            <CardHeader>
              <CardTitle>{t('accountCard.title')}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="flex min-w-0 items-center gap-2 text-foreground">
                <UserRound className="h-4 w-4 shrink-0" />
                <span className="truncate">{session.user.email}</span>
              </div>
              <p>{t('accountCard.note')}</p>
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  )
}
