'use client'

import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { authClient, getAuthBaseUrl } from '@/lib/auth-client'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type DeviceAuthorizationStatus = 'pending' | 'approved' | 'denied'

function cleanUserCode(value: string) {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, '')
}

function formatUserCode(value: string) {
  const cleaned = cleanUserCode(value)
  return cleaned.replace(/(.{4})(?=.)/g, '$1-')
}

function buildRedirectTarget(userCode: string) {
  const query = new URLSearchParams()

  if (userCode) {
    query.set('user_code', userCode)
  }

  const suffix = query.toString()
  return `/device${suffix ? `?${suffix}` : ''}`
}

async function requestAuthJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${getAuthBaseUrl()}${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    cache: 'no-store',
    ...init,
  })

  if (!response.ok) {
    const data = (await response.json().catch(() => null)) as
      | { error?: string; error_description?: string }
      | null
    throw new Error(
      data?.error_description || data?.error || `Request failed with status ${response.status}`
    )
  }

  return response.json() as Promise<T>
}

export default function DevicePage() {
  const searchParams = useSearchParams()
  const { data: session, isPending: isSessionPending } = authClient.useSession()

  const initialCode = useMemo(
    () => formatUserCode(searchParams.get('user_code') || ''),
    [searchParams]
  )

  const [userCode, setUserCode] = useState(initialCode)
  const [status, setStatus] = useState<DeviceAuthorizationStatus | null>(null)
  const [error, setError] = useState('')
  const [statusBusy, setStatusBusy] = useState(false)
  const [activeAction, setActiveAction] = useState<'approve' | 'deny' | ''>('')

  const normalizedCode = cleanUserCode(userCode)
  const redirectTarget = buildRedirectTarget(normalizedCode)
  const accountLabel = session?.user.username || session?.user.email || session?.user.name || 'account'

  const refreshStatus = async (code = normalizedCode) => {
    if (!code) {
      setError('Enter the code from pastevault login.')
      setStatus(null)
      return
    }

    setStatusBusy(true)
    setError('')

    try {
      const result = await requestAuthJSON<{ status: DeviceAuthorizationStatus }>(
        `/device?user_code=${encodeURIComponent(code)}`
      )
      setStatus(result.status)
    } catch (requestError) {
      setStatus(null)
      setError((requestError as Error).message || 'Unable to verify code')
    } finally {
      setStatusBusy(false)
    }
  }

  useEffect(() => {
    setUserCode(initialCode)
    if (!initialCode) {
      setStatus(null)
      setError('')
      return
    }

    void refreshStatus(cleanUserCode(initialCode))
  }, [initialCode])

  const handleApprove = async () => {
    if (!normalizedCode) {
      setError('Enter the code from pastevault login.')
      return
    }

    setActiveAction('approve')
    setError('')

    try {
      await requestAuthJSON<{ success: boolean }>('/device/approve', {
        method: 'POST',
        body: JSON.stringify({ userCode: normalizedCode }),
      })
      setStatus('approved')
    } catch (requestError) {
      setError((requestError as Error).message || 'Unable to approve device')
    } finally {
      setActiveAction('')
    }
  }

  const handleDeny = async () => {
    if (!normalizedCode) {
      setError('Enter the code from pastevault login.')
      return
    }

    setActiveAction('deny')
    setError('')

    try {
      await requestAuthJSON<{ success: boolean }>('/device/deny', {
        method: 'POST',
        body: JSON.stringify({ userCode: normalizedCode }),
      })
      setStatus('denied')
    } catch (requestError) {
      setError((requestError as Error).message || 'Unable to deny device')
    } finally {
      setActiveAction('')
    }
  }

  if (isSessionPending) {
    return (
      <div className="app-frame py-10">
        <div className="tool-panel">
          <div className="tool-panel-body flex items-center gap-3 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading device approval...
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">CLI login</p>
            <h1 className="text-xl font-semibold sm:text-2xl">Approve PasteVault CLI</h1>
          </div>
          <div className="flex items-center gap-2">
            <Button asChild variant="outline">
              <Link href="/">Back to editor</Link>
            </Button>
          </div>
        </div>
      </header>

      <div className="app-frame grid gap-4 py-6 lg:grid-cols-[minmax(0,1fr)_320px]">
        <Card>
          <CardHeader>
            <CardTitle>Link this device to your account</CardTitle>
            <CardDescription>
              Approving a device only lets future CLI uploads show up in your account.
              Downloads remain share-based and do not require login.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="user-code">CLI code</Label>
              <div className="flex flex-col gap-3 sm:flex-row">
                <Input
                  id="user-code"
                  value={userCode}
                  onChange={(event) => setUserCode(formatUserCode(event.target.value))}
                  placeholder="ABCD-EFGH"
                  autoCapitalize="characters"
                  autoCorrect="off"
                  spellCheck={false}
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void refreshStatus()}
                  disabled={statusBusy || activeAction !== ''}
                >
                  {statusBusy ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Checking
                    </>
                  ) : (
                    'Check code'
                  )}
                </Button>
              </div>
            </div>

            {error ? (
              <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                {error}
              </div>
            ) : null}

            {!session ? (
              <div className="rounded-lg border border-border/80 bg-muted/40 px-4 py-4 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Sign in first</p>
                <p className="mt-1">
                  You need a PasteVault account session in this browser before you can approve the
                  device.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button asChild>
                    <Link href={`/account?redirectTo=${encodeURIComponent(redirectTarget)}`}>
                      Sign in or create account
                    </Link>
                  </Button>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-4 py-4 text-sm text-emerald-950">
                Signed in as <span className="font-medium">{accountLabel}</span>
              </div>
            )}

            {status ? (
              <div className="rounded-lg border border-border/80 bg-muted/30 px-4 py-4 text-sm">
                <p className="font-medium text-foreground">Current status</p>
                <p className="mt-1 capitalize text-muted-foreground">{status}</p>
              </div>
            ) : null}

            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                onClick={() => void handleApprove()}
                disabled={!session || !normalizedCode || activeAction !== '' || status === 'approved'}
              >
                {activeAction === 'approve' ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Approving
                  </>
                ) : (
                  'Approve device'
                )}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => void handleDeny()}
                disabled={!session || !normalizedCode || activeAction !== '' || status === 'denied'}
              >
                {activeAction === 'deny' ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Denying
                  </>
                ) : (
                  'Deny device'
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Terminal flow</CardTitle>
            <CardDescription>Use the CLI on the machine you want to link.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>1. Run <code className="rounded bg-muted px-1.5 py-0.5">pastevault login</code>.</p>
            <p>2. Open the verification link or paste the code here.</p>
            <p>3. Approve the device. Future <code className="rounded bg-muted px-1.5 py-0.5">pastevault put</code> uploads from that machine will appear in your account.</p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
