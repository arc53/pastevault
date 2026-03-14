'use client'

import { type ReactNode, useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { CopyButton } from '@/components/copy-button'
import { MarkdownRenderer } from '@/components/markdown-renderer'
import { ThemeToggle } from '@/components/theme-toggle'
import { useGetFileShare } from '@/hooks/usePaste'
import { api } from '@/lib/api'
import {
  base64urlDecode,
  decodeKeyString,
  deriveKeyFromPassword,
  extractKeyFromFragment,
} from '@/lib/crypto'
import {
  decryptFileChunk,
  decryptFileShareManifest,
  formatBytes,
} from '@/lib/file-shares'
import { FileShareManifest, FileShareManifestFile } from '@/types'
import {
  AlertCircle,
  Download,
  Eye,
  FileText,
  Folder,
  Loader2,
  Lock,
  Menu,
  X,
} from 'lucide-react'

interface FileSystemWritable {
  write(data: BufferSource): Promise<void>
  close(): Promise<void>
  abort?(): Promise<void>
}

interface SaveFileHandle {
  createWritable(): Promise<FileSystemWritable>
}

interface SavePickerWindow extends Window {
  showSaveFilePicker?: (options?: { suggestedName?: string }) => Promise<SaveFileHandle>
}

export default function ViewFileSharePage() {
  const t = useTranslations('common')
  const tFiles = useTranslations('fileShare')
  const tErrors = useTranslations('errors')
  const tFormats = useTranslations('formats')
  const tAccessibility = useTranslations('accessibility')
  const params = useParams()
  const router = useRouter()
  const slug = params?.slug as string

  const [password, setPassword] = useState('')
  const [manifest, setManifest] = useState<FileShareManifest | null>(null)
  const [shareKey, setShareKey] = useState<Uint8Array | null>(null)
  const [isDecrypting, setIsDecrypting] = useState(false)
  const [decryptionError, setDecryptionError] = useState('')
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [downloadStatus, setDownloadStatus] = useState<Record<string, string>>({})

  const { data: share, isLoading, error } = useGetFileShare(slug)
  const supportsSavePicker =
    typeof window !== 'undefined' &&
    typeof (window as SavePickerWindow).showSaveFilePicker === 'function'

  useEffect(() => {
    if (!share) {
      return
    }

    const attemptDecryption = async () => {
      setIsDecrypting(true)
      setDecryptionError('')

      try {
        const fragmentKey = extractKeyFromFragment()

        if (fragmentKey && !share.salt) {
          const key = decodeKeyString(fragmentKey)
          const decryptedManifest = decryptFileShareManifest(
            share.manifest_ciphertext,
            share.manifest_nonce,
            key,
            share.metadata.slug
          )

          setShareKey(key)
          setManifest(decryptedManifest)
          setShowPasswordPrompt(false)
        } else if (share.salt && share.kdf_params) {
          setShowPasswordPrompt(true)
        } else {
          setDecryptionError(tErrors('invalidFormat'))
        }
      } catch (decryptError) {
        console.error('File share decryption failed:', decryptError)
        setDecryptionError(tFiles('decryptionError'))
      } finally {
        setIsDecrypting(false)
      }
    }

    attemptDecryption()
  }, [share, tErrors, tFiles])

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
    if (!share || !password) {
      return
    }

    setIsDecrypting(true)
    setDecryptionError('')

    try {
      const { key } = await deriveKeyFromPassword(
        password,
        base64urlDecode(share.salt!)
      )

      const decryptedManifest = decryptFileShareManifest(
        share.manifest_ciphertext,
        share.manifest_nonce,
        key,
        share.metadata.slug
      )

      setShareKey(key)
      setManifest(decryptedManifest)
      setShowPasswordPrompt(false)
    } catch (passwordError) {
      console.error('Password decryption failed:', passwordError)
      setDecryptionError(tErrors('incorrectPassword'))
    } finally {
      setIsDecrypting(false)
    }
  }

  const getTimeRemaining = (expiresAt: string | null) => {
    if (!expiresAt) return tFiles('neverExpires')

    const now = Date.now()
    const expiry = new Date(expiresAt).getTime()
    const diff = expiry - now

    if (diff <= 0) return tFiles('expired')

    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))

    if (days > 0) return tFiles('daysRemaining', { days, hours })
    if (hours > 0) return tFiles('hoursRemaining', { hours, minutes })
    return tFiles('minutesRemaining', { minutes })
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
            <Button onClick={action}>{actionLabel}</Button>
          )}
        </div>
      </div>
    </div>
  )

  const downloadFile = async (file: FileShareManifestFile) => {
    if (!shareKey || !share) {
      return
    }

    const setProgress = (processedBytes: number) => {
      const percentage = Math.min(
        100,
        Math.round((processedBytes / Math.max(file.size, 1)) * 100)
      )
      setDownloadStatus((current) => ({
        ...current,
        [file.id]: `${percentage}%`,
      }))
    }

    setDownloadStatus((current) => ({
      ...current,
      [file.id]: tFiles('preparingDownload'),
    }))

    let processedBytes = 0
    let writable: FileSystemWritable | null = null

    try {
      const saveWindow = window as SavePickerWindow

      if (saveWindow.showSaveFilePicker) {
        const handle = await saveWindow.showSaveFilePicker({
          suggestedName: file.name,
        })

        writable = await handle.createWritable()

        for (const chunk of file.chunks) {
          const encryptedChunk = await api.downloadFileShareChunk(
            share.metadata.slug,
            file.id,
            chunk.index
          )
          const plaintextChunk = decryptFileChunk(
            encryptedChunk,
            chunk.nonce,
            shareKey,
            share.metadata.slug,
            file.id,
            chunk.index
          )
          const outputChunk = new Uint8Array(plaintextChunk)

          await writable.write(outputChunk)
          processedBytes += chunk.plaintext_size
          setProgress(processedBytes)
        }

        await writable.close()
      } else {
        const parts: BlobPart[] = []

        for (const chunk of file.chunks) {
          const encryptedChunk = await api.downloadFileShareChunk(
            share.metadata.slug,
            file.id,
            chunk.index
          )
          const plaintextChunk = decryptFileChunk(
            encryptedChunk,
            chunk.nonce,
            shareKey,
            share.metadata.slug,
            file.id,
            chunk.index
          )
          const outputChunk = new Uint8Array(plaintextChunk)

          parts.push(
            outputChunk.buffer.slice(
              outputChunk.byteOffset,
              outputChunk.byteOffset + outputChunk.byteLength
            )
          )
          processedBytes += chunk.plaintext_size
          setProgress(processedBytes)
        }

        const blob = new Blob(parts, {
          type: file.type || 'application/octet-stream',
        })
        const blobUrl = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = blobUrl
        link.download = file.name
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        URL.revokeObjectURL(blobUrl)
      }

      setDownloadStatus((current) => ({
        ...current,
        [file.id]: tFiles('downloadReady'),
      }))
    } catch (downloadError) {
      console.error('File download failed:', downloadError)

      if (writable?.abort) {
        await writable.abort().catch(() => undefined)
      }

      setDownloadStatus((current) => ({
        ...current,
        [file.id]: tFiles('downloadFailed'),
      }))
    }
  }

  if (isLoading) {
    return renderCenteredState(
      tFiles('loadingShare'),
      tFiles('loadingShare'),
      undefined,
      undefined,
      <Loader2 className="h-4 w-4 animate-spin" />
    )
  }

  if (error) {
    const errorMessage = (error as Error)?.message || 'Unknown error'
    const isNotFound = (error as { status?: number })?.status === 404
    const isExpired = errorMessage.includes('expired')
    const title = isNotFound ? tFiles('notFound') : isExpired ? tFiles('expiredTitle') : t('error')
    const description = isNotFound
      ? tFiles('notFoundDesc')
      : isExpired
        ? tFiles('expiredDesc')
        : errorMessage

    return renderCenteredState(
      title,
      description,
      tFiles('createNew'),
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
              <h1 className="text-lg font-semibold">{tFiles('passwordProtected')}</h1>
            </div>
          </div>
          <div className="tool-panel-body space-y-4">
            <p className="text-sm text-muted-foreground">{tFiles('passwordPrompt')}</p>

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
                  {tFiles('decrypting')}
                </>
              ) : (
                tFiles('decryptShare')
              )}
            </Button>
          </div>
        </div>
      </div>
    )
  }

  if (isDecrypting) {
    return renderCenteredState(
      tFiles('decryptingShare'),
      tFiles('decryptingShare'),
      undefined,
      undefined,
      <Loader2 className="h-4 w-4 animate-spin" />
    )
  }

  if (decryptionError) {
    return renderCenteredState(
      tErrors('decryptionFailed'),
      decryptionError,
      tFiles('createNew'),
      () => router.push('/'),
      <AlertCircle className="h-4 w-4 text-red-500" />
    )
  }

  if (!manifest || !share) {
    return null
  }

  const sharedNote = manifest.paste
  const hasSharedNote = Boolean(
    sharedNote && (sharedNote.title.trim() || sharedNote.body.trim())
  )
  const toFencedMarkdown = (body: string, lang?: string) => {
    const useTilde = body.includes('```')
    const fence = useTilde ? '~~~~' : '```'
    const langId = lang ? lang : ''
    return `${fence}${langId}\n${body}\n${fence}`
  }
  const renderedNoteBody =
    sharedNote && sharedNote.body.trim()
      ? sharedNote.render_mode === 'plain'
        ? toFencedMarkdown(sharedNote.body, sharedNote.language_hint)
        : sharedNote.body
      : ''
  const noteFormatLabel = sharedNote
    ? sharedNote.render_mode === 'markdown'
      ? tFormats('markdown')
      : sharedNote.language_hint
        ? sharedNote.language_hint
        : tFormats('plain')
    : ''

  return (
    <div className="pb-8">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/86 backdrop-blur-xl">
        <div className="app-frame flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0">
            <p className="tool-label">{share.metadata.slug}</p>
            <Link href="/" className="text-xl font-semibold hover:text-foreground/85 sm:text-2xl">
              PasteVault
            </Link>
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 md:flex xl:hidden">
              <CopyButton
                getValue={() => window.location.href}
                variant="outline"
                size="sm"
                label={tFiles('copyUrl')}
              />
              <Link href="/">
                <Button size="sm">{tFiles('createNew')}</Button>
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
                <h2 className="text-lg font-semibold">{tFiles('title')}</h2>
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
                getValue={() => window.location.href}
                variant="outline"
                size="sm"
                label={tFiles('copyUrl')}
              />
              <Link href="/">
                <Button className="w-full">{tFiles('createNew')}</Button>
              </Link>
            </div>
          </div>
        </div>
      )}

      <div className="app-frame py-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-4">
            {hasSharedNote && sharedNote && (
              <section className="tool-panel">
                <div className="tool-panel-header">
                  <div className="min-w-0">
                    <p className="tool-label">{tFiles('noteTitle')}</p>
                    <h1 className="text-lg font-semibold">
                      {sharedNote.title.trim() || tFiles('noteTitle')}
                    </h1>
                  </div>
                  <span className="meta-chip">
                    <FileText className="h-3.5 w-3.5" />
                    <strong>{noteFormatLabel}</strong>
                  </span>
                </div>
                {renderedNoteBody && (
                  <div className="p-0">
                    <MarkdownRenderer content={renderedNoteBody} className="p-4 sm:p-6" />
                  </div>
                )}
              </section>
            )}

            <section className="tool-panel">
              <div className="tool-panel-header">
                <div className="min-w-0">
                  <p className="tool-label">{share.metadata.slug}</p>
                  <h1 className="text-lg font-semibold">{tFiles('title')}</h1>
                </div>
                <span className="meta-chip">
                  <Folder className="h-3.5 w-3.5" />
                  <strong>{manifest.files.length}</strong>
                </span>
              </div>

              <div className="tool-panel-body space-y-3">
                {manifest.files.map((file) => (
                  <div
                    key={file.id}
                    className="flex flex-col gap-3 rounded-sm border border-border/70 bg-background/55 p-3 md:flex-row md:items-center md:justify-between"
                  >
                    <div className="min-w-0">
                      <div className="break-all text-sm font-medium">{file.name}</div>
                      <div className="mt-1 text-[11px] text-muted-foreground">
                        {formatBytes(file.size)} · {file.chunks.length} {tFiles('chunks')}
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {downloadStatus[file.id] && (
                        <span className="min-w-16 text-right text-xs text-muted-foreground">
                          {downloadStatus[file.id]}
                        </span>
                      )}
                      <Button onClick={() => void downloadFile(file)}>
                        <Download className="h-4 w-4" />
                        {tFiles('download')}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>

              <div className="status-bar">
                <span>
                  <Eye className="h-3 w-3" />
                  <span className="text-foreground">
                    {share.metadata.view_count} {tFiles('views')}
                  </span>
                </span>
                <span>
                  <Lock className="h-3 w-3" />
                  <span className="text-foreground">
                    {share.salt ? tFiles('passwordLocked') : tFiles('zeroKnowledge')}
                  </span>
                </span>
                <span>
                  <span className="text-foreground">
                    {manifest.files.length} {tFiles('files')} · {formatBytes(Number(share.metadata.total_size_bytes))}
                  </span>
                </span>
                <span>
                  <span className="text-foreground">
                    {share.metadata.expires_at
                      ? getTimeRemaining(share.metadata.expires_at)
                      : tFiles('neverExpires')}
                  </span>
                </span>
              </div>
            </section>
          </div>

          <aside className="space-y-4">
            <div className="hidden xl:block tool-panel">
              <div className="tool-panel-header">
                <div>
                  <p className="tool-label">{t('options')}</p>
                  <h2 className="text-lg font-semibold">{tFiles('createNew')}</h2>
                </div>
              </div>
              <div className="tool-panel-body space-y-3">
                <CopyButton
                  getValue={() => window.location.href}
                  variant="outline"
                  className="w-full justify-start"
                  label={tFiles('copyUrl')}
                />
                <Link href="/" className="block">
                  <Button className="w-full">{tFiles('createNew')}</Button>
                </Link>
              </div>
            </div>

            <div className="tool-panel">
              <div className="tool-panel-header">
                <div>
                  <p className="tool-label">{tFiles('files')}</p>
                  <h2 className="text-lg font-semibold">
                    {manifest.files.length} · {formatBytes(Number(share.metadata.total_size_bytes))}
                  </h2>
                </div>
              </div>
              <div className="tool-panel-body space-y-3 text-sm text-muted-foreground">
                <div className="flex items-center justify-between gap-3">
                  <span>{tFiles('files')}</span>
                  <span className="font-mono text-foreground">{manifest.files.length}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span>TTL</span>
                  <span className="font-mono text-foreground">
                    {share.metadata.expires_at
                      ? getTimeRemaining(share.metadata.expires_at)
                      : tFiles('neverExpires')}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span>{t('password')}</span>
                  <span className="font-mono text-foreground">
                    {share.salt ? tFiles('passwordLocked') : tFiles('zeroKnowledge')}
                  </span>
                </div>
                {!supportsSavePicker && (
                  <div className="rounded-sm border border-amber-500/25 bg-amber-500/10 p-3 text-amber-700 dark:text-amber-200">
                    {tFiles('browserDownloadWarning')}
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
