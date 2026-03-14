'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
      } catch (decryptionError) {
        console.error('File share decryption failed:', decryptionError)
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
    return (
      <div className="container mx-auto py-8 px-4 max-w-4xl">
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin" />
            <span className="ml-2">{tFiles('loadingShare')}</span>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    const errorMessage = (error as Error)?.message || 'Unknown error'
    const isNotFound = (error as { status?: number })?.status === 404
    const isExpired = errorMessage.includes('expired')

    return (
      <div className="container mx-auto py-8 px-4 max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center gap-2 justify-center text-red-600">
              <AlertCircle className="h-5 w-5" />
              {isNotFound ? tFiles('notFound') : isExpired ? tFiles('expiredTitle') : t('error')}
            </CardTitle>
            <CardDescription>
              {isNotFound && tFiles('notFoundDesc')}
              {isExpired && tFiles('expiredDesc')}
              {!isNotFound && !isExpired && errorMessage}
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button onClick={() => router.push('/')}>{tFiles('createNew')}</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (showPasswordPrompt) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-md">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center gap-2 justify-center">
              <Lock className="h-5 w-5" />
              {tFiles('passwordProtected')}
            </CardTitle>
            <CardDescription>{tFiles('passwordPrompt')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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
              <div className="text-sm text-red-600 bg-red-50 dark:bg-red-950 p-3 rounded">
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
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {tFiles('decrypting')}
                </>
              ) : (
                tFiles('decryptShare')
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (isDecrypting) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-4xl">
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin" />
            <span className="ml-2">{tFiles('decryptingShare')}</span>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (decryptionError) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center gap-2 justify-center text-red-600">
              <AlertCircle className="h-5 w-5" />
              {tErrors('decryptionFailed')}
            </CardTitle>
            <CardDescription>{decryptionError}</CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button onClick={() => router.push('/')}>{tFiles('createNew')}</Button>
          </CardContent>
        </Card>
      </div>
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
    <div>
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <Link href="/">
              <h1 className="text-xl font-semibold cursor-pointer">{t('pasteVault')}</h1>
            </Link>

            <div className="flex items-center gap-2">
              <div className="hidden md:flex items-center gap-4">
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
                className="md:hidden inline-flex items-center justify-center rounded-md p-2 hover:bg-muted"
                aria-controls="mobile-menu"
                aria-expanded={mobileMenuOpen}
                aria-label={tAccessibility('openMenu')}
                onClick={() => setMobileMenuOpen(true)}
              >
                <Menu className="h-6 w-6" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {mobileMenuOpen && (
        <div className="md:hidden">
          <div className="fixed inset-0 z-40 bg-black/50" onClick={() => setMobileMenuOpen(false)} />
          <div
            className="fixed inset-y-0 right-0 z-50 w-80 max-w-[90vw] bg-background shadow-lg p-4 overflow-y-auto"
            role="dialog"
            aria-modal="true"
            id="mobile-menu"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">{t('options')}</h2>
              <button
                className="inline-flex items-center justify-center rounded-md p-2 hover:bg-muted"
                aria-label={tAccessibility('closeMenu')}
                onClick={() => setMobileMenuOpen(false)}
              >
                <X className="h-6 w-6" />
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

      <div className="container mx-auto px-4 py-6">
        <div className="space-y-4">
          {hasSharedNote && sharedNote && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <FileText className="h-4 w-4" />
                  {sharedNote.title.trim() || tFiles('noteTitle')}
                </CardTitle>
                <CardDescription>{noteFormatLabel}</CardDescription>
              </CardHeader>
              {renderedNoteBody && (
                <CardContent>
                  <MarkdownRenderer content={renderedNoteBody} />
                </CardContent>
              )}
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Folder className="h-4 w-4" />
                {tFiles('title')}
              </CardTitle>
              <CardDescription>{tFiles('description')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {manifest.files.map((file) => (
                <div
                  key={file.id}
                  className="flex flex-col gap-3 rounded-lg border p-4 md:flex-row md:items-center md:justify-between"
                >
                  <div className="space-y-1">
                    <div className="font-medium break-all">{file.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {formatBytes(file.size)} · {file.chunks.length} {tFiles('chunks')}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {downloadStatus[file.id] && (
                      <span className="text-sm text-muted-foreground min-w-16 text-right">
                        {downloadStatus[file.id]}
                      </span>
                    )}
                    <Button onClick={() => void downloadFile(file)}>
                      <Download className="mr-2 h-4 w-4" />
                      {tFiles('download')}
                    </Button>
                  </div>
                </div>
              ))}

              {!supportsSavePicker && (
                <div className="rounded-lg bg-amber-50 p-4 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-100">
                  {tFiles('browserDownloadWarning')}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="flex items-center justify-between text-sm text-muted-foreground bg-muted/30 px-4 py-2 rounded-md">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Eye className="h-3 w-3" />
                {share.metadata.view_count} {tFiles('views')}
              </div>
              <div className="flex items-center gap-2">
                <Lock className="h-3 w-3" />
                {share.salt ? tFiles('passwordLocked') : tFiles('zeroKnowledge')}
              </div>
              <div>
                {manifest.files.length} {tFiles('files')} ·{' '}
                {formatBytes(Number(share.metadata.total_size_bytes))}
              </div>
            </div>
            <div>
              {share.metadata.expires_at ? (
                <span className="text-amber-600">
                  {getTimeRemaining(share.metadata.expires_at)}
                </span>
              ) : (
                tFiles('neverExpires')
              )}
            </div>
          </div>
        </div>
      </div>
      <ThemeToggle />
    </div>
  )
}
