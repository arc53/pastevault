'use client'

import { type ReactNode, useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { useTranslations } from 'next-intl'
import {
  AlertCircle,
  Eye,
  Flame,
  Loader2,
  Lock,
  Menu,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { MarkdownRenderer } from '@/components/markdown-renderer'
import { useGetPaste } from '@/hooks/usePaste'
import { ThemeToggle } from '@/components/theme-toggle'
import { CopyButton } from '@/components/copy-button'
import {
  decryptPaste,
  decryptPasteWithPassword,
  extractKeyFromFragment,
} from '@/lib/crypto'
import { PasteContent } from '@/types'

export default function ViewPastePage() {
  const t = useTranslations('common')
  const tView = useTranslations('viewPaste')
  const tErrors = useTranslations('errors')
  const tAccessibility = useTranslations('accessibility')
  const params = useParams()
  const router = useRouter()
  const slug = params?.slug as string

  const [password, setPassword] = useState('')
  const [content, setContent] = useState<PasteContent | null>(null)
  const [isDecrypting, setIsDecrypting] = useState(false)
  const [decryptionError, setDecryptionError] = useState('')
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const { data: paste, isLoading, error } = useGetPaste(slug)

  useEffect(() => {
    if (!paste) return

    const attemptDecryption = async () => {
      setIsDecrypting(true)
      setDecryptionError('')

      try {
        const fragmentKey = extractKeyFromFragment()

        if (fragmentKey && !paste.salt) {
          const keyBytes = new Uint8Array(
            atob(fragmentKey.replace(/-/g, '+').replace(/_/g, '/'))
              .split('')
              .map((character) => character.charCodeAt(0))
          )

          const decryptedContent = await decryptPaste(
            paste.ciphertext,
            paste.nonce,
            keyBytes,
            paste.metadata.slug
          )

          setContent(decryptedContent)
        } else if (paste.salt && paste.kdf_params) {
          setShowPasswordPrompt(true)
        } else {
          setDecryptionError('Invalid paste format or missing decryption key')
        }
      } catch (decryptError) {
        console.error('Decryption failed:', decryptError)
        setDecryptionError('Failed to decrypt paste. Invalid key or corrupted data.')
      } finally {
        setIsDecrypting(false)
      }
    }

    attemptDecryption()
  }, [paste])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMobileMenuOpen(false)
      }
    }

    if (mobileMenuOpen) {
      document.body.classList.add('overflow-hidden')
      window.addEventListener('keydown', onKeyDown)
    } else {
      document.body.classList.remove('overflow-hidden')
    }

    return () => {
      document.body.classList.remove('overflow-hidden')
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [mobileMenuOpen])

  const handlePasswordDecrypt = async () => {
    if (!paste || !password) return

    setIsDecrypting(true)
    setDecryptionError('')

    try {
      const decryptedContent = await decryptPasteWithPassword(
        paste.ciphertext,
        paste.nonce,
        paste.salt!,
        paste.kdf_params!,
        password,
        paste.metadata.slug
      )

      setContent(decryptedContent)
      setShowPasswordPrompt(false)
    } catch (decryptError) {
      console.error('Password decryption failed:', decryptError)
      setDecryptionError('Incorrect password or corrupted data')
    } finally {
      setIsDecrypting(false)
    }
  }

  const getTimeRemaining = (expiresAt: string | null) => {
    if (!expiresAt) return tView('neverExpires')

    const now = new Date().getTime()
    const expiry = new Date(expiresAt).getTime()
    const diff = expiry - now

    if (diff <= 0) return tView('expired')

    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))

    if (days > 0) return tView('daysRemaining', { days, hours })
    if (hours > 0) return tView('hoursRemaining', { hours, minutes })
    return tView('minutesRemaining', { minutes })
  }

  const renderCenteredState = (
    title: string,
    description?: string,
    actionLabel?: string,
    action?: () => void,
    icon?: ReactNode
  ) => (
    <div className="app-frame py-8">
      <div className="mx-auto max-w-2xl tool-panel">
        <div className="tool-panel-header">
          <div className="min-w-0">
            <p className="tool-label">{slug}</p>
            <h1 className="text-lg font-semibold">{title}</h1>
          </div>
        </div>
        <div className="tool-panel-body space-y-4">
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            {icon}
            <span>{description}</span>
          </div>
          {actionLabel && action && (
            <Button onClick={action}>
              {actionLabel}
            </Button>
          )}
        </div>
      </div>
    </div>
  )

  if (isLoading) {
    return renderCenteredState(
      tView('loadingPaste'),
      tView('loadingPaste'),
      undefined,
      undefined,
      <Loader2 className="h-4 w-4 animate-spin" />
    )
  }

  if (error) {
    const errorMessage = (error as Error)?.message || 'Unknown error'
    const isNotFound = (error as { status?: number })?.status === 404
    const isBurned = errorMessage.includes('burned')
    const isExpired = errorMessage.includes('expired')
    const title = isNotFound
      ? tErrors('pasteNotFound')
      : isBurned
        ? tErrors('pasteBurned')
        : isExpired
          ? tErrors('pasteExpired')
          : t('error')
    const description =
      isNotFound
        ? tErrors('pasteNotFoundDesc')
        : isBurned
          ? tErrors('pasteBurnedDesc')
          : isExpired
            ? tErrors('pasteExpiredDesc')
            : errorMessage

    return renderCenteredState(
      title,
      description,
      tErrors('createNewPaste'),
      () => router.push('/'),
      <AlertCircle className="h-4 w-4 text-red-500" />
    )
  }

  if (showPasswordPrompt) {
    return (
      <div className="app-frame py-8">
        <div className="mx-auto max-w-md tool-panel">
          <div className="tool-panel-header">
            <div className="min-w-0">
              <p className="tool-label">{slug}</p>
              <h1 className="text-lg font-semibold">{tView('passwordProtected')}</h1>
            </div>
          </div>
          <div className="tool-panel-body space-y-4">
            <p className="text-sm text-muted-foreground">{tView('passwordPrompt')}</p>

            <div className="space-y-2">
              <Label htmlFor="password">{t('password')}</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={`${t('password')}...`}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && password) {
                    void handlePasswordDecrypt()
                  }
                }}
              />
            </div>

            {decryptionError && (
              <div className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200">
                {decryptionError}
              </div>
            )}

            <Button
              onClick={() => void handlePasswordDecrypt()}
              disabled={!password || isDecrypting}
              className="w-full"
            >
              {isDecrypting ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {tView('decrypting')}
                </>
              ) : (
                tView('decryptPaste')
              )}
            </Button>
          </div>
        </div>
      </div>
    )
  }

  if (isDecrypting) {
    return renderCenteredState(
      tView('decryptingPaste'),
      tView('decryptingPaste'),
      undefined,
      undefined,
      <Loader2 className="h-4 w-4 animate-spin" />
    )
  }

  if (decryptionError) {
    return renderCenteredState(
      tErrors('decryptionFailed'),
      decryptionError,
      tErrors('createNewPaste'),
      () => router.push('/'),
      <AlertCircle className="h-4 w-4 text-red-500" />
    )
  }

  if (!content || !paste) {
    return null
  }

  const toFencedMarkdown = (body: string, lang?: string) => {
    const useTilde = body.includes('```')
    const fence = useTilde ? '~~~~' : '```'
    const langId = lang ? lang : ''
    return `${fence}${langId}\n${body}\n${fence}`
  }

  const renderedBody =
    content.render_mode === 'plain'
      ? toFencedMarkdown(content.body, content.language_hint)
      : content.body

  const displayTitle =
    content.title?.trim() && content.title.trim() !== 'Untitled'
      ? content.title
      : paste.metadata.slug

  const modeLabel = content.language_hint || content.render_mode

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">{paste.metadata.slug}</p>
            <Link href="/" className="text-xl font-semibold hover:text-foreground/85 sm:text-2xl">
              PasteVault
            </Link>
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 md:flex xl:hidden">
              <CopyButton
                getValue={() => content.body}
                variant="outline"
                size="sm"
                label={tView('copyContent')}
              />
              <CopyButton
                getValue={() => window.location.href}
                variant="outline"
                size="sm"
                label={tView('copyUrl')}
              />
              <Link href="/">
                <Button size="sm">{tView('createNew')}</Button>
              </Link>
            </div>
            <button
              className="inline-flex h-9 w-9 items-center justify-center rounded-sm border border-border/80 bg-background/70 hover:bg-accent/40 md:hidden"
              aria-controls="mobile-menu"
              aria-expanded={mobileMenuOpen}
              aria-label={tAccessibility('openMenu')}
              onClick={() => setMobileMenuOpen(true)}
            >
              <Menu className="h-5 w-5" />
            </button>
          </div>
        </div>
      </header>

      {mobileMenuOpen && (
        <div className="md:hidden">
          <div className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={() => setMobileMenuOpen(false)} />
          <div
            className="utility-drawer"
            role="dialog"
            aria-modal="true"
            id="mobile-menu"
          >
            <div className="mb-4 flex items-center justify-between">
              <div>
                <p className="tool-label">{t('options')}</p>
                <h2 className="text-lg font-semibold">{displayTitle}</h2>
              </div>
              <button
                className="inline-flex h-9 w-9 items-center justify-center rounded-sm border border-border/80 bg-background/70 hover:bg-accent/40"
                aria-label={tAccessibility('closeMenu')}
                onClick={() => setMobileMenuOpen(false)}
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3">
              <CopyButton
                getValue={() => content.body}
                variant="outline"
                size="sm"
                label={tView('copyContent')}
              />
              <CopyButton
                getValue={() => window.location.href}
                variant="outline"
                size="sm"
                label={tView('copyUrl')}
              />
              <Link href="/">
                <Button className="w-full">{tView('createNew')}</Button>
              </Link>
            </div>
          </div>
        </div>
      )}

      <div className="app-frame py-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
          <section className="tool-panel">
            <div className="tool-panel-header">
              <div className="min-w-0">
                <p className="tool-label">{paste.metadata.slug}</p>
                <h1 className="text-lg font-semibold sm:text-xl">{displayTitle}</h1>
              </div>
              <span className="meta-chip">
                <strong>{modeLabel}</strong>
              </span>
            </div>

            <div className="p-0">
              <MarkdownRenderer
                content={renderedBody}
                className="min-h-[420px] p-4 sm:p-6"
              />
            </div>

            <div className="status-bar">
              <span>
                <Eye className="h-3 w-3" />
                <span className="text-foreground">
                  {paste.metadata.view_count} {tView('views')}
                </span>
              </span>
              <span>
                <Lock className="h-3 w-3" />
                <span className="text-foreground">
                  {paste.salt ? t('password') : tView('zeroKnowledge')}
                </span>
              </span>
              {paste.metadata.burn_after_read && (
                <span className="text-orange-600 dark:text-orange-300">
                  <Flame className="h-3 w-3" />
                  {tView('burnsAfterReading')}
                </span>
              )}
              <span>
                <span className="text-foreground">
                  {paste.metadata.expires_at
                    ? getTimeRemaining(paste.metadata.expires_at)
                    : tView('neverExpires')}
                </span>
              </span>
            </div>
          </section>

          <aside className="space-y-4">
            <div className="hidden xl:block tool-panel">
              <div className="tool-panel-header">
                <div>
                  <p className="tool-label">{t('options')}</p>
                  <h2 className="text-lg font-semibold">{tView('createNew')}</h2>
                </div>
              </div>
              <div className="tool-panel-body space-y-3">
                <CopyButton
                  getValue={() => content.body}
                  variant="outline"
                  className="w-full justify-start"
                  label={tView('copyContent')}
                />
                <CopyButton
                  getValue={() => window.location.href}
                  variant="outline"
                  className="w-full justify-start"
                  label={tView('copyUrl')}
                />
                <Link href="/" className="block">
                  <Button className="w-full">{tView('createNew')}</Button>
                </Link>
              </div>
            </div>

            <div className="tool-panel">
              <div className="tool-panel-header">
                <div>
                  <p className="tool-label">{tView('views')}</p>
                  <h2 className="text-lg font-semibold">{paste.metadata.view_count}</h2>
                </div>
              </div>
              <div className="tool-panel-body space-y-3 text-sm text-muted-foreground">
                <div className="flex items-center justify-between gap-3">
                  <span>{tView('views')}</span>
                  <span className="font-mono text-foreground">{paste.metadata.view_count}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span>{t('password')}</span>
                  <span className="font-mono text-foreground">
                    {paste.salt ? t('password') : tView('zeroKnowledge')}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span>TTL</span>
                  <span className="font-mono text-foreground">
                    {paste.metadata.expires_at
                      ? getTimeRemaining(paste.metadata.expires_at)
                      : tView('neverExpires')}
                  </span>
                </div>
                {paste.metadata.burn_after_read && (
                  <div className="rounded-sm border border-orange-500/25 bg-orange-500/10 p-3 text-orange-700 dark:text-orange-200">
                    {tView('burnsAfterReading')}
                  </div>
                )}
              </div>
            </div>
          </aside>
        </div>
      </div>

      <ThemeToggle />
    </div>
  )
}
