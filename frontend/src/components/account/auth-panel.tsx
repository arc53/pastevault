'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { useTranslations } from 'next-intl'
import { useQueryClient } from '@tanstack/react-query'
import { Lock } from 'lucide-react'
import { authClient } from '@/lib/auth-client'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const USERNAME_PREFIXES = ['arc', 'cipher', 'ember', 'neon', 'nova', 'onyx', 'pixel', 'solar', 'velvet', 'vivid']
const USERNAME_SUFFIXES = ['atlas', 'drift', 'echo', 'forge', 'fox', 'harbor', 'quill', 'raven', 'signal', 'vault']

function generateUsernameSuggestion() {
  const prefix = USERNAME_PREFIXES[Math.floor(Math.random() * USERNAME_PREFIXES.length)] || 'cipher'
  const suffix = USERNAME_SUFFIXES[Math.floor(Math.random() * USERNAME_SUFFIXES.length)] || 'vault'
  const number = Math.floor(Math.random() * 900 + 100)

  return `${prefix}${suffix}${number}`
}

// The signed-out account page: what accounts are for, plus sign-in/sign-up.
export function AuthPanel({ signupEnabled, onSignedIn }: { signupEnabled: boolean; onSignedIn: () => void }) {
  const t = useTranslations('account.auth')
  const tAccount = useTranslations('account')
  const queryClient = useQueryClient()
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [authError, setAuthError] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [signInForm, setSignInForm] = useState({ identifier: '', password: '' })
  const [signUpForm, setSignUpForm] = useState({ email: '', username: '', password: '' })

  useEffect(() => {
    if (!signupEnabled && mode === 'signup') {
      setMode('signin')
      return
    }

    if (mode !== 'signup') {
      return
    }

    setSignUpForm((current) =>
      current.username.trim() ? current : { ...current, username: generateUsernameSuggestion() }
    )
  }, [mode, signupEnabled])

  const afterAuth = async () => {
    await queryClient.invalidateQueries()
    onSignedIn()
  }

  const handleSignIn = async () => {
    setAuthBusy(true)
    setAuthError('')

    try {
      const identifier = signInForm.identifier.trim()
      const result = identifier.includes('@')
        ? await authClient.signIn.email({ email: identifier, password: signInForm.password })
        : await authClient.signIn.username({ username: identifier, password: signInForm.password })

      if (result.error) {
        setAuthError(result.error.message || t('signInFailed'))
      } else {
        await afterAuth()
      }
    } catch (error) {
      setAuthError((error as Error).message || t('signInFailed'))
    } finally {
      setAuthBusy(false)
    }
  }

  const handleSignUp = async () => {
    if (!signupEnabled) {
      return
    }

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
        setAuthError(result.error.message || t('signUpFailed'))
      } else {
        await afterAuth()
      }
    } catch (error) {
      setAuthError((error as Error).message || t('signUpFailed'))
    } finally {
      setAuthBusy(false)
    }
  }

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">{tAccount('label')}</p>
            <h1 className="text-xl font-semibold sm:text-2xl">{t('heading')}</h1>
          </div>
          <Button asChild variant="outline">
            <Link href="/">{tAccount('backToEditor')}</Link>
          </Button>
        </div>
      </header>

      <div className="app-frame grid gap-4 py-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <Card>
          <CardHeader>
            <CardTitle>{t('introTitle')}</CardTitle>
            <CardDescription>{t('introDescription')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm text-muted-foreground">
            <p>{t('introMetadata')}</p>
            <p>{t('introFragment')}</p>
            <div className="rounded-sm border border-border/70 bg-muted/35 p-4">
              <div className="flex items-start gap-3">
                <Lock className="mt-0.5 h-4 w-4 text-primary" />
                <div className="space-y-1">
                  <p className="font-medium text-foreground">{t('trackedTitle')}</p>
                  <p>{t('trackedBody')}</p>
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
                aria-pressed={mode === 'signin'}
                variant={mode === 'signin' ? 'default' : 'outline'}
                onClick={() => setMode('signin')}
              >
                {t('signIn')}
              </Button>
              {signupEnabled && (
                <Button
                  type="button"
                  aria-pressed={mode === 'signup'}
                  variant={mode === 'signup' ? 'default' : 'outline'}
                  onClick={() => setMode('signup')}
                >
                  {t('createAccount')}
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {mode === 'signin' ? (
              <form
                className="space-y-4"
                onSubmit={(event) => {
                  event.preventDefault()
                  void handleSignIn()
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="identifier">{t('identifier')}</Label>
                  <Input
                    id="identifier"
                    autoComplete="username"
                    value={signInForm.identifier}
                    onChange={(event) => setSignInForm((current) => ({ ...current, identifier: event.target.value }))}
                    placeholder={t('identifierPlaceholder')}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="signin-password">{t('password')}</Label>
                  <Input
                    id="signin-password"
                    type="password"
                    autoComplete="current-password"
                    value={signInForm.password}
                    onChange={(event) => setSignInForm((current) => ({ ...current, password: event.target.value }))}
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={authBusy || !signInForm.identifier.trim() || !signInForm.password}
                >
                  {authBusy ? t('signingIn') : t('signIn')}
                </Button>
              </form>
            ) : (
              <form
                className="space-y-4"
                onSubmit={(event) => {
                  event.preventDefault()
                  void handleSignUp()
                }}
              >
                <div className="space-y-2">
                  <Label htmlFor="signup-username">{t('username')}</Label>
                  <Input
                    id="signup-username"
                    autoComplete="username"
                    value={signUpForm.username}
                    onChange={(event) => setSignUpForm((current) => ({ ...current, username: event.target.value }))}
                    placeholder="ciphervault314"
                  />
                  <p className="text-xs text-muted-foreground">{t('usernameHint')}</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="signup-email">{t('email')}</Label>
                  <Input
                    id="signup-email"
                    type="email"
                    autoComplete="email"
                    value={signUpForm.email}
                    onChange={(event) => setSignUpForm((current) => ({ ...current, email: event.target.value }))}
                    placeholder="alex@example.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="signup-password">{t('password')}</Label>
                  <Input
                    id="signup-password"
                    type="password"
                    autoComplete="new-password"
                    value={signUpForm.password}
                    onChange={(event) => setSignUpForm((current) => ({ ...current, password: event.target.value }))}
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={
                    authBusy || !signUpForm.email.trim() || !signUpForm.username.trim() || !signUpForm.password
                  }
                >
                  {authBusy ? t('creatingAccount') : t('createAccount')}
                </Button>
              </form>
            )}

            {authError && (
              <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200" role="alert">
                {authError}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
