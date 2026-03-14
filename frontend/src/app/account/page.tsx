'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Eye, KeyRound, Loader2, Lock, Trash2, UserRound } from 'lucide-react'
import { authClient } from '@/lib/auth-client'
import { useAccountShares, useDeleteAccountShare } from '@/hooks/useAccount'
import { formatBytes } from '@/lib/file-shares'
import { AccountShare, OwnedShareStatus, OwnedShareType } from '@/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

const USERNAME_PREFIXES = [
  'arc',
  'cipher',
  'ember',
  'neon',
  'nova',
  'onyx',
  'pixel',
  'solar',
  'velvet',
  'vivid',
]

const USERNAME_SUFFIXES = [
  'atlas',
  'drift',
  'echo',
  'forge',
  'fox',
  'harbor',
  'quill',
  'raven',
  'signal',
  'vault',
]

function generateUsernameSuggestion() {
  const prefix =
    USERNAME_PREFIXES[Math.floor(Math.random() * USERNAME_PREFIXES.length)] || 'cipher'
  const suffix =
    USERNAME_SUFFIXES[Math.floor(Math.random() * USERNAME_SUFFIXES.length)] || 'vault'
  const number = Math.floor(Math.random() * 900 + 100)

  return `${prefix}${suffix}${number}`
}

function formatDateTime(value: string | null) {
  if (!value) {
    return 'Never'
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function getShareHref(share: AccountShare) {
  return share.share_type === 'paste' ? `/p/${share.slug}` : `/f/${share.slug}`
}

function getShareLabel(shareType: OwnedShareType) {
  return shareType === 'paste' ? 'Paste' : 'Files'
}

function getStatusLabel(status: OwnedShareStatus) {
  switch (status) {
    case 'uploading':
      return 'Uploading'
    case 'active':
      return 'Active'
    case 'burned':
      return 'Burned'
    case 'expired':
      return 'Expired'
    case 'deleted':
      return 'Deleted'
    case 'abandoned':
      return 'Abandoned'
  }
}

function getShareSizeLabel(share: AccountShare) {
  if (share.share_type === 'paste') {
    return share.burn_after_read ? 'Burn after read' : 'Standard share'
  }

  if (!share.total_size_bytes) {
    return `${share.file_count || 0} files`
  }

  return `${share.file_count || 0} files · ${formatBytes(Number(share.total_size_bytes))}`
}

export default function AccountPage() {
  const queryClient = useQueryClient()
  const { data: session, isPending: isSessionPending } = authClient.useSession()
  const deleteShare = useDeleteAccountShare()

  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [authError, setAuthError] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [statusFilter, setStatusFilter] = useState<'all' | OwnedShareStatus>('all')
  const [typeFilter, setTypeFilter] = useState<'all' | OwnedShareType>('all')
  const [signInForm, setSignInForm] = useState({
    identifier: '',
    password: '',
  })
  const [signUpForm, setSignUpForm] = useState({
    email: '',
    username: '',
    password: '',
  })

  const sharesQuery = useAccountShares(
    {
      share_type: typeFilter === 'all' ? undefined : typeFilter,
      status: statusFilter === 'all' ? undefined : statusFilter,
    },
    Boolean(session)
  )

  const handleSignIn = async () => {
    setAuthBusy(true)
    setAuthError('')

    try {
      const identifier = signInForm.identifier.trim()
      const result = identifier.includes('@')
        ? await authClient.signIn.email({
            email: identifier,
            password: signInForm.password,
          })
        : await authClient.signIn.username({
            username: identifier,
            password: signInForm.password,
          })

      if (result.error) {
        setAuthError(result.error.message || 'Unable to sign in')
      } else {
        await queryClient.invalidateQueries({ queryKey: ['account-shares'] })
      }
    } catch (error) {
      setAuthError((error as Error).message || 'Unable to sign in')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleSignUp = async () => {
    setAuthBusy(true)
    setAuthError('')

    try {
      const username = signUpForm.username.trim()
      const result = await authClient.signUp.email({
        name: username,
        email: signUpForm.email.trim(),
        username,
        displayUsername: username,
        password: signUpForm.password,
      })

      if (result.error) {
        setAuthError(result.error.message || 'Unable to create account')
      } else {
        await queryClient.invalidateQueries({ queryKey: ['account-shares'] })
      }
    } catch (error) {
      setAuthError((error as Error).message || 'Unable to create account')
    } finally {
      setAuthBusy(false)
    }
  }

  const handleSignOut = async () => {
    setAuthError('')

    try {
      await authClient.signOut()
      await queryClient.invalidateQueries({ queryKey: ['account-shares'] })
    } catch (error) {
      setAuthError((error as Error).message || 'Unable to sign out')
    }
  }

  const handleDeleteShare = async (shareId: string) => {
    try {
      await deleteShare.mutateAsync(shareId)
      await queryClient.invalidateQueries({ queryKey: ['account-shares'] })
    } catch (error) {
      setAuthError((error as Error).message || 'Unable to delete share')
    }
  }

  const shares = sharesQuery.data?.shares || []
  const activeCount = shares.filter((share) => share.status === 'active').length
  const totalViews = shares.reduce((total, share) => total + share.view_count, 0)

  useEffect(() => {
    if (mode !== 'signup') {
      return
    }

    setSignUpForm((current) => {
      if (current.username.trim()) {
        return current
      }

      return {
        ...current,
        username: generateUsernameSuggestion(),
      }
    })
  }, [mode])

  if (isSessionPending) {
    return (
      <div className="app-frame py-10">
        <div className="tool-panel">
          <div className="tool-panel-body flex items-center gap-3 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading account...
          </div>
        </div>
      </div>
    )
  }

  if (!session) {
    return (
      <div className="pb-8">
        <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
          <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
            <div className="min-w-0">
              <p className="tool-label">Account</p>
              <h1 className="text-xl font-semibold sm:text-2xl">PasteVault Accounts</h1>
            </div>
            <div className="flex items-center gap-2">
              <Button asChild variant="outline">
                <Link href="/">Back to editor</Link>
              </Button>
            </div>
          </div>
        </header>

        <div className="app-frame grid gap-4 py-6 lg:grid-cols-[minmax(0,1fr)_360px]">
          <Card>
            <CardHeader>
              <CardTitle>Optional account, anonymous shares still supported</CardTitle>
              <CardDescription>
                Sign in to track the shares you create, monitor views, and delete active shares.
                Anonymous creation and viewing continue to work exactly the same.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-muted-foreground">
              <p>
                The dashboard stores share metadata only: slug, status, expiry, counts, and whether
                the share uses password-based decryption.
              </p>
              <p>
                Zero-knowledge links that depend on a URL fragment are not recoverable from the
                server, so keep the original link if you want to reopen those later.
              </p>
              <div className="rounded-sm border border-border/70 bg-muted/35 p-4">
                <div className="flex items-start gap-3">
                  <Lock className="mt-0.5 h-4 w-4 text-primary" />
                  <div className="space-y-1">
                    <p className="font-medium text-foreground">What gets tracked</p>
                    <p>Creation time, status transitions, expiry, first/last view, and total views.</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant={mode === 'signin' ? 'default' : 'outline'}
                  onClick={() => setMode('signin')}
                >
                  Sign in
                </Button>
                <Button
                  type="button"
                  variant={mode === 'signup' ? 'default' : 'outline'}
                  onClick={() => setMode('signup')}
                >
                  Create account
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {mode === 'signin' ? (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="identifier">Username or email</Label>
                    <Input
                      id="identifier"
                      value={signInForm.identifier}
                      onChange={(event) =>
                        setSignInForm((current) => ({
                          ...current,
                          identifier: event.target.value,
                        }))
                      }
                      placeholder="you@example.com or your_username"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signin-password">Password</Label>
                    <Input
                      id="signin-password"
                      type="password"
                      value={signInForm.password}
                      onChange={(event) =>
                        setSignInForm((current) => ({
                          ...current,
                          password: event.target.value,
                        }))
                      }
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          void handleSignIn()
                        }
                      }}
                    />
                  </div>
                  <Button
                    className="w-full"
                    onClick={() => void handleSignIn()}
                    disabled={authBusy || !signInForm.identifier.trim() || !signInForm.password}
                  >
                    {authBusy ? 'Signing in...' : 'Sign in'}
                  </Button>
                </>
              ) : (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="signup-username">Username</Label>
                    <Input
                      id="signup-username"
                      value={signUpForm.username}
                      onChange={(event) =>
                        setSignUpForm((current) => ({
                          ...current,
                          username: event.target.value,
                        }))
                      }
                      placeholder="ciphervault314"
                    />
                    <p className="text-xs text-muted-foreground">
                      Prefilled with a generated handle. Change it if you want.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-email">Email</Label>
                    <Input
                      id="signup-email"
                      type="email"
                      value={signUpForm.email}
                      onChange={(event) =>
                        setSignUpForm((current) => ({
                          ...current,
                          email: event.target.value,
                        }))
                      }
                      placeholder="alex@example.com"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-password">Password</Label>
                    <Input
                      id="signup-password"
                      type="password"
                      value={signUpForm.password}
                      onChange={(event) =>
                        setSignUpForm((current) => ({
                          ...current,
                          password: event.target.value,
                        }))
                      }
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          void handleSignUp()
                        }
                      }}
                    />
                  </div>
                  <Button
                    className="w-full"
                    onClick={() => void handleSignUp()}
                    disabled={
                      authBusy ||
                      !signUpForm.email.trim() ||
                      !signUpForm.username.trim() ||
                      !signUpForm.password
                    }
                  >
                    {authBusy ? 'Creating account...' : 'Create account'}
                  </Button>
                </>
              )}

              {authError && (
                <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
                  {authError}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">Tracked shares</p>
            <h1 className="text-xl font-semibold sm:text-2xl">
              {session.user.username || session.user.name || 'Account'}
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link href="/">Back to editor</Link>
            </Button>
            <Button variant="outline" onClick={() => void handleSignOut()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <div className="app-frame grid gap-4 py-6 xl:grid-cols-[minmax(0,1fr)_320px]">
        <section className="space-y-4">
          <Card>
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <CardTitle>Share dashboard</CardTitle>
                <CardDescription>
                  The dashboard keeps metadata only. Original zero-knowledge fragment keys are not
                  stored server-side.
                </CardDescription>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row">
                <Select
                  value={typeFilter}
                  onValueChange={(value) => setTypeFilter(value as 'all' | OwnedShareType)}
                >
                  <SelectTrigger className="w-full sm:w-[140px]">
                    <SelectValue placeholder="Share type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All types</SelectItem>
                    <SelectItem value="paste">Pastes</SelectItem>
                    <SelectItem value="file_share">Files</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={statusFilter}
                  onValueChange={(value) => setStatusFilter(value as 'all' | OwnedShareStatus)}
                >
                  <SelectTrigger className="w-full sm:w-[160px]">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="uploading">Uploading</SelectItem>
                    <SelectItem value="burned">Burned</SelectItem>
                    <SelectItem value="expired">Expired</SelectItem>
                    <SelectItem value="deleted">Deleted</SelectItem>
                    <SelectItem value="abandoned">Abandoned</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {sharesQuery.isLoading ? (
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading tracked shares...
                </div>
              ) : sharesQuery.isError ? (
                <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
                  {sharesQuery.error instanceof Error
                    ? sharesQuery.error.message
                    : 'Unable to load tracked shares'}
                </div>
              ) : shares.length === 0 ? (
                <div className="rounded-sm border border-border/70 bg-muted/25 p-4 text-sm text-muted-foreground">
                  No tracked shares yet. Create a paste or file share while signed in and it will
                  appear here.
                </div>
              ) : (
                shares.map((share) => (
                  <div
                    key={share.id}
                    className="rounded-sm border border-border/70 bg-background/55 p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="tool-label">{getShareLabel(share.share_type)}</p>
                        <h2 className="font-semibold">{share.slug}</h2>
                        <p className="mt-1 text-sm text-muted-foreground">
                          {getStatusLabel(share.status)} · {getShareSizeLabel(share)}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {share.is_password_protected ? (
                          <Button asChild variant="outline" size="sm">
                            <Link href={getShareHref(share)}>
                              <ExternalLink className="h-3.5 w-3.5" />
                              Open
                            </Link>
                          </Button>
                        ) : (
                          <span className="meta-chip">
                            <KeyRound className="h-3 w-3" />
                            Original link required
                          </span>
                        )}
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!share.can_delete || deleteShare.isPending}
                          onClick={() => void handleDeleteShare(share.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Delete
                        </Button>
                      </div>
                    </div>

                    <div className="mt-4 grid gap-3 text-sm text-muted-foreground sm:grid-cols-2 xl:grid-cols-4">
                      <div>
                        <p className="tool-label">Created</p>
                        <p>{formatDateTime(share.created_at)}</p>
                      </div>
                      <div>
                        <p className="tool-label">Expires</p>
                        <p>{formatDateTime(share.expires_at)}</p>
                      </div>
                      <div>
                        <p className="tool-label">Views</p>
                        <p className="inline-flex items-center gap-2">
                          <Eye className="h-3.5 w-3.5" />
                          {share.view_count}
                        </p>
                      </div>
                      <div>
                        <p className="tool-label">Last viewed</p>
                        <p>{share.last_viewed_at ? formatDateTime(share.last_viewed_at) : 'Not yet viewed'}</p>
                      </div>
                    </div>

                    {share.is_password_protected ? (
                      <p className="mt-3 text-sm text-muted-foreground">
                        This share can be reopened from the dashboard because it uses password-based
                        decryption.
                      </p>
                    ) : (
                      <p className="mt-3 text-sm text-muted-foreground">
                        This share uses a random client key stored in the original URL fragment. The
                        dashboard can track and delete it, but it cannot reconstruct that key.
                      </p>
                    )}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </section>

        <aside className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>At a glance</CardTitle>
              <CardDescription>Live metrics for the filtered result set.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between rounded-sm border border-border/70 bg-muted/25 px-3 py-2">
                <span className="text-muted-foreground">Tracked shares</span>
                <strong>{shares.length}</strong>
              </div>
              <div className="flex items-center justify-between rounded-sm border border-border/70 bg-muted/25 px-3 py-2">
                <span className="text-muted-foreground">Active shares</span>
                <strong>{activeCount}</strong>
              </div>
              <div className="flex items-center justify-between rounded-sm border border-border/70 bg-muted/25 px-3 py-2">
                <span className="text-muted-foreground">Total views</span>
                <strong>{totalViews}</strong>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Account</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <div className="flex items-center gap-2 text-foreground">
                <UserRound className="h-4 w-4" />
                <span>{session.user.email}</span>
              </div>
              <p>
                Shares created before you signed in remain anonymous. Only shares created while this
                session is authenticated are tracked here.
              </p>
            </CardContent>
          </Card>
        </aside>
      </div>

      {authError && (
        <div className="app-frame">
          <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
            {authError}
          </div>
        </div>
      )}
    </div>
  )
}
