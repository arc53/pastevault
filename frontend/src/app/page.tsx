'use client'

import { useEffect, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { nanoid } from 'nanoid'
import QRCode from 'react-qr-code'
import {
  AlertCircle,
  Flame,
  Lock,
  Menu,
  Paperclip,
  Save,
  Share,
  Trash2,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { CopyButton } from '@/components/copy-button'
import { Editor } from '@/components/editor'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ThemeToggle } from '@/components/theme-toggle'
import { useCreateFileShare, useCreatePaste, useGetCapabilities } from '@/hooks/usePaste'
import { api } from '@/lib/api'
import {
  createFileShareUrl,
  createShareUrl,
  encryptPaste,
  encryptPasteWithPassword,
} from '@/lib/crypto'
import {
  encryptFileChunk,
  encryptFileShareManifest,
  formatBytes,
  prepareFileShareEncryption,
} from '@/lib/file-shares'
import { clearDraft, getDraftAge, loadDraft, saveDraft } from '@/lib/drafts'
import { Draft, FileShareManifest, PasteContent } from '@/types'

type ShareKind = 'paste' | 'files' | 'mixed'

const DEFAULT_EXPIRY_HOURS = 24

function formatFileCount(count: number) {
  return count === 1 ? '1 file' : `${count} files`
}

function getSelectedFileKey(file: File) {
  return `${file.name}:${file.size}:${file.lastModified}`
}

function buildPasteContent(
  title: string,
  body: string,
  format: string,
  requireBody: boolean
): PasteContent | null {
  const trimmedTitle = title.trim()
  const trimmedBody = body.trim()

  if (requireBody ? !trimmedBody : !(trimmedTitle || trimmedBody)) {
    return null
  }

  return {
    title: trimmedTitle,
    body,
    render_mode:
      format === 'markdown' || format === 'plain'
        ? (format as 'markdown' | 'plain')
        : 'plain',
    language_hint: format !== 'markdown' && format !== 'plain' ? format : undefined,
  }
}

export default function CreatePastePage() {
  const t = useTranslations('common')
  const tCreate = useTranslations('createPaste')
  const tExpiration = useTranslations('expiration')
  const tFormats = useTranslations('formats')
  const tShare = useTranslations('shareSuccess')
  const tFiles = useTranslations('fileShare')
  const tAccessibility = useTranslations('accessibility')

  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [format, setFormat] = useState('markdown')
  const [expiresInHours, setExpiresInHours] = useState(DEFAULT_EXPIRY_HOURS)
  const [burnAfterRead, setBurnAfterRead] = useState(false)
  const [passwordProtected, setPasswordProtected] = useState(false)
  const [password, setPassword] = useState('')
  const [shareUrl, setShareUrl] = useState('')
  const [lastShareKind, setLastShareKind] = useState<ShareKind>('paste')
  const [isCreating, setIsCreating] = useState(false)
  const [hasDraft, setHasDraft] = useState(false)
  const [draftAge, setDraftAge] = useState('')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [selectedFiles, setSelectedFiles] = useState<File[]>([])
  const [createError, setCreateError] = useState('')
  const [uploadProgress, setUploadProgress] = useState(0)

  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const createPaste = useCreatePaste()
  const createFileShare = useCreateFileShare()
  const { data: capabilities } = useGetCapabilities()

  const totalSelectedFileSize = selectedFiles.reduce(
    (total, file) => total + file.size,
    0
  )
  const hasAttachedFiles = selectedFiles.length > 0
  const fileShareCapabilities = capabilities?.file_shares
  const fileSharesEnabled = fileShareCapabilities?.enabled ?? false
  const optionalNoteContent = buildPasteContent(title, body, format, false)

  useEffect(() => {
    const draft = loadDraft()
    if (draft) {
      setHasDraft(true)
      setDraftAge(getDraftAge(draft))
    }
  }, [])

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

  const loadFromDraft = () => {
    const draft = loadDraft()
    if (draft) {
      setTitle(draft.title)
      setBody(draft.body)
      setFormat(draft.language_hint || 'markdown')
      setExpiresInHours(draft.expires_in_hours || DEFAULT_EXPIRY_HOURS)
      setBurnAfterRead(draft.burn_after_read)
      setPasswordProtected(draft.password_protected)
      setHasDraft(false)
    }
  }

  const saveCurrentDraft = () => {
    if (title || body) {
      saveDraft({
        title,
        body,
        language_hint: format !== 'markdown' && format !== 'plain' ? format : undefined,
        expires_in_hours: expiresInHours,
        burn_after_read: burnAfterRead,
        password_protected: passwordProtected,
      } satisfies Omit<Draft, 'saved_at'>)
    }
  }

  const handleCreatePaste = async () => {
    const content = buildPasteContent(title, body, format, true)

    if (!content) {
      return
    }

    setIsCreating(true)
    setCreateError('')

    try {
      const clientSlug = nanoid(12)
      let encryptionResult

      if (passwordProtected && password) {
        encryptionResult = await encryptPasteWithPassword(content, password, clientSlug)
      } else {
        const randomResult = await encryptPaste(content, clientSlug)
        encryptionResult = {
          ciphertext: randomResult.ciphertext,
          nonce: randomResult.nonce,
          key: randomResult.key,
        }
      }

      const response = await createPaste.mutateAsync({
        ciphertext: encryptionResult.ciphertext,
        nonce: encryptionResult.nonce,
        slug: clientSlug,
        salt: 'salt' in encryptionResult ? encryptionResult.salt : undefined,
        kdf_params: 'kdf_params' in encryptionResult ? encryptionResult.kdf_params : undefined,
        expires_in_hours: expiresInHours,
        burn_after_read: burnAfterRead,
      })

      setShareUrl(
        createShareUrl(
          response.slug,
          'key' in encryptionResult ? encryptionResult.key : undefined
        )
      )
      setLastShareKind('paste')
      clearDraft()
      setHasDraft(false)
    } catch (error) {
      console.error('Failed to create paste:', error)
      setCreateError((error as Error).message || t('error'))
    } finally {
      setIsCreating(false)
    }
  }

  const handleCreateFileShare = async () => {
    if (!hasAttachedFiles) {
      return
    }

    if (!fileShareCapabilities || !fileSharesEnabled) {
      setCreateError(tFiles('notConfigured'))
      return
    }

    if (selectedFiles.length > fileShareCapabilities.max_files) {
      setCreateError(
        tFiles('tooManyFiles', { count: fileShareCapabilities.max_files })
      )
      return
    }

    if (totalSelectedFileSize > fileShareCapabilities.max_share_size_bytes) {
      setCreateError(
        tFiles('shareTooLarge', {
          size: formatBytes(fileShareCapabilities.max_share_size_bytes),
        })
      )
      return
    }

    setIsCreating(true)
    setCreateError('')
    setUploadProgress(0)

    try {
      const clientSlug = nanoid(12)
      const encryption = await prepareFileShareEncryption(
        passwordProtected ? password : undefined
      )

      await createFileShare.mutateAsync({
        slug: clientSlug,
        expires_in_hours: expiresInHours,
        salt: encryption.salt,
        kdf_params: encryption.kdf_params,
        file_count: selectedFiles.length,
        total_size_bytes: totalSelectedFileSize,
      })

      const manifestFiles: FileShareManifest['files'] = []
      let uploadedBytes = 0

      for (const file of selectedFiles) {
        const fileId = nanoid(16)
        const chunks = []

        for (
          let chunkIndex = 0, offset = 0;
          offset < file.size;
          chunkIndex += 1, offset += fileShareCapabilities.chunk_size_bytes
        ) {
          const chunkBlob = file.slice(
            offset,
            offset + fileShareCapabilities.chunk_size_bytes
          )
          const plaintextChunk = new Uint8Array(await chunkBlob.arrayBuffer())
          const encryptedChunk = await encryptFileChunk(
            plaintextChunk,
            encryption.key,
            clientSlug,
            fileId,
            chunkIndex
          )

          await api.uploadFileShareChunk(
            clientSlug,
            fileId,
            chunkIndex,
            encryptedChunk.ciphertext
          )

          chunks.push({
            index: chunkIndex,
            nonce: encryptedChunk.nonce,
            plaintext_size: plaintextChunk.length,
          })

          uploadedBytes += plaintextChunk.length
          setUploadProgress(
            Math.min(
              100,
              Math.round((uploadedBytes / Math.max(totalSelectedFileSize, 1)) * 100)
            )
          )
        }

        manifestFiles.push({
          id: fileId,
          name: file.name,
          size: file.size,
          type: file.type,
          last_modified: file.lastModified,
          chunks,
        })
      }

      const manifest = {
        version: 'v1',
        paste: optionalNoteContent ?? undefined,
        files: manifestFiles,
      } satisfies FileShareManifest
      const encryptedManifest = await encryptFileShareManifest(
        manifest,
        encryption.key,
        clientSlug
      )

      await api.completeFileShare(clientSlug, encryptedManifest)

      setShareUrl(
        createFileShareUrl(
          clientSlug,
          passwordProtected ? undefined : encryption.key
        )
      )
      setLastShareKind(optionalNoteContent ? 'mixed' : 'files')
      setSelectedFiles([])
      setUploadProgress(0)
      if (optionalNoteContent) {
        clearDraft()
        setHasDraft(false)
      }
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    } catch (error) {
      console.error('Failed to create file share:', error)
      setCreateError((error as Error).message || t('error'))
    } finally {
      setIsCreating(false)
    }
  }

  const handleCreate = async () => {
    if (hasAttachedFiles) {
      await handleCreateFileShare()
      return
    }

    await handleCreatePaste()
  }

  const createNew = () => {
    setTitle('')
    setBody('')
    setFormat('markdown')
    setPassword('')
    setPasswordProtected(false)
    setBurnAfterRead(false)
    setSelectedFiles([])
    setCreateError('')
    setUploadProgress(0)
    setShareUrl('')
    setLastShareKind('paste')
    setHasDraft(false)
    clearDraft()

    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const selectFiles = (files: FileList | null) => {
    if (!files) {
      return
    }

    const nextFiles = Array.from(files)
    setCreateError('')
    setBurnAfterRead(false)
    setSelectedFiles((current) => {
      const currentKeys = new Set(current.map(getSelectedFileKey))
      const uniqueNextFiles = nextFiles.filter((file) => !currentKeys.has(getSelectedFileKey(file)))
      return [...current, ...uniqueNextFiles]
    })

    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const removeFile = (index: number) => {
    setSelectedFiles((current) => current.filter((_, currentIndex) => currentIndex !== index))
  }

  const clearFiles = () => {
    setSelectedFiles([])
    setUploadProgress(0)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const canSubmit =
    (Boolean(body.trim()) || hasAttachedFiles) &&
    !(passwordProtected && !password) &&
    (!hasAttachedFiles || Boolean(fileShareCapabilities && fileSharesEnabled))

  const renderFormatSelect = (fullWidth = false) => (
    <Select value={format} onValueChange={setFormat}>
      <SelectTrigger className={fullWidth ? 'w-full' : 'w-[180px]'}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="markdown">{tFormats('markdown')}</SelectItem>
        <SelectItem value="plain">{tFormats('plain')}</SelectItem>
        <SelectItem value="javascript">{tFormats('javascript')}</SelectItem>
        <SelectItem value="typescript">{tFormats('typescript')}</SelectItem>
        <SelectItem value="python">{tFormats('python')}</SelectItem>
        <SelectItem value="java">{tFormats('java')}</SelectItem>
        <SelectItem value="cpp">{tFormats('cpp')}</SelectItem>
        <SelectItem value="c">{tFormats('c')}</SelectItem>
        <SelectItem value="csharp">{tFormats('csharp')}</SelectItem>
        <SelectItem value="php">{tFormats('php')}</SelectItem>
        <SelectItem value="go">{tFormats('go')}</SelectItem>
        <SelectItem value="rust">{tFormats('rust')}</SelectItem>
        <SelectItem value="sql">{tFormats('sql')}</SelectItem>
        <SelectItem value="json">{tFormats('json')}</SelectItem>
        <SelectItem value="yaml">{tFormats('yaml')}</SelectItem>
        <SelectItem value="xml">{tFormats('xml')}</SelectItem>
        <SelectItem value="html">{tFormats('html')}</SelectItem>
        <SelectItem value="css">{tFormats('css')}</SelectItem>
        <SelectItem value="bash">{tFormats('bash')}</SelectItem>
        <SelectItem value="bat">{tFormats('bat')}</SelectItem>
        <SelectItem value="powershell">{tFormats('powershell')}</SelectItem>
      </SelectContent>
    </Select>
  )

  const renderAttachButton = (mobile = false) => (
    <Button
      type="button"
      variant={hasAttachedFiles ? 'default' : 'outline'}
      size={mobile ? 'sm' : 'default'}
      className="gap-2"
      onClick={() => fileInputRef.current?.click()}
    >
      <Paperclip className="h-4 w-4" />
      <span>{tFiles('attachFiles')}</span>
      {hasAttachedFiles && (
        <span className="inline-flex min-w-5 items-center justify-center rounded-full bg-background/20 px-1.5 text-xs font-medium">
          {selectedFiles.length}
        </span>
      )}
    </Button>
  )

  if (shareUrl) {
    const shareTitle =
      lastShareKind === 'mixed'
        ? tShare('mixedTitle')
        : lastShareKind === 'files'
          ? tShare('fileTitle')
          : tShare('pasteTitle')
    const shareDescription =
      lastShareKind === 'mixed'
        ? tShare('mixedDescription')
        : lastShareKind === 'files'
          ? tShare('fileDescription')
          : tShare('pasteDescription')
    const createAnotherLabel =
      lastShareKind === 'mixed'
        ? tShare('createAnotherShare')
        : lastShareKind === 'files'
          ? tShare('createAnotherFile')
          : tShare('createAnotherPaste')
    const viewLabel =
      lastShareKind === 'mixed'
        ? tShare('viewShare')
        : lastShareKind === 'files'
          ? tShare('viewFiles')
          : tShare('viewPaste')

    return (
      <div className="container mx-auto max-w-2xl px-4 py-8">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center justify-center gap-2">
              <Share className="h-5 w-5" />
              {shareTitle}
            </CardTitle>
            <CardDescription>{shareDescription}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>{tShare('shareUrl')}</Label>
              <div className="flex gap-2">
                <Input value={shareUrl} readOnly className="font-mono text-sm" />
                <CopyButton value={shareUrl} variant="outline" />
              </div>
            </div>

            <div className="space-y-2">
              <Label>QR code</Label>
              <div className="flex justify-center">
                <div className="rounded bg-white p-3">
                  <QRCode value={shareUrl} size={180} bgColor="#FFFFFF" fgColor="#000000" />
                </div>
              </div>
            </div>

            <div className="rounded-lg bg-muted/50 p-4">
              <div className="flex items-start gap-2">
                <AlertCircle className="mt-0.5 h-4 w-4 text-amber-500" />
                <div className="text-sm">
                  <p className="font-medium">{tShare('important')}</p>
                  <p className="mt-1 text-muted-foreground">
                    {passwordProtected
                      ? tShare('passwordProtectedWarning')
                      : tShare('urlWarning')}
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <Button onClick={createNew} className="flex-1">
                {createAnotherLabel}
              </Button>
              <Button onClick={() => window.location.assign(shareUrl)} variant="outline">
                {viewLabel}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div>
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={(event) => selectFiles(event.target.files)}
      />

      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4">
          <div className="flex h-16 items-center justify-between">
            <h1 className="text-xl font-semibold">{t('pasteVault')}</h1>

            <div className="flex items-center gap-2">
              <div className="hidden items-center gap-4 md:flex">
                {renderAttachButton()}

                <Select
                  value={expiresInHours.toString()}
                  onValueChange={(value) => setExpiresInHours(Number(value))}
                >
                  <SelectTrigger className="w-[120px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">{tExpiration('1hour')}</SelectItem>
                    <SelectItem value="6">{tExpiration('6hours')}</SelectItem>
                    <SelectItem value="24">{tExpiration('1day')}</SelectItem>
                    <SelectItem value="168">{tExpiration('1week')}</SelectItem>
                    <SelectItem value="720">{tExpiration('1month')}</SelectItem>
                  </SelectContent>
                </Select>

                {!hasAttachedFiles && (
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={burnAfterRead}
                      onChange={(event) => setBurnAfterRead(event.target.checked)}
                      className="rounded"
                    />
                    <Flame className="h-4 w-4" />
                    {tCreate('burnAfterReading')}
                  </label>
                )}

                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={passwordProtected}
                      onChange={(event) => setPasswordProtected(event.target.checked)}
                      className="rounded"
                    />
                    <Lock className="h-4 w-4" />
                    {t('password')}
                  </label>
                  {passwordProtected && (
                    <Input
                      type="password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder={tCreate('enterPassword')}
                      className="h-9 w-32"
                    />
                  )}
                </div>
              </div>

              <div className="md:hidden">{renderAttachButton(true)}</div>

              <button
                className="inline-flex items-center justify-center rounded-md p-2 hover:bg-muted md:hidden"
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
            className="fixed inset-y-0 right-0 z-50 w-80 max-w-[90vw] overflow-y-auto bg-background p-4 shadow-lg"
            role="dialog"
            aria-modal="true"
            id="mobile-menu"
          >
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold">{t('options')}</h2>
              <button
                className="inline-flex items-center justify-center rounded-md p-2 hover:bg-muted"
                aria-label={tAccessibility('closeMenu')}
                onClick={() => setMobileMenuOpen(false)}
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{tCreate('expiresIn')}</Label>
                <Select
                  value={expiresInHours.toString()}
                  onValueChange={(value) => setExpiresInHours(Number(value))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">{tExpiration('1hour')}</SelectItem>
                    <SelectItem value="6">{tExpiration('6hours')}</SelectItem>
                    <SelectItem value="24">{tExpiration('1day')}</SelectItem>
                    <SelectItem value="168">{tExpiration('1week')}</SelectItem>
                    <SelectItem value="720">{tExpiration('1month')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {!hasAttachedFiles && (
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={burnAfterRead}
                    onChange={(event) => setBurnAfterRead(event.target.checked)}
                    className="rounded"
                  />
                  <Flame className="h-4 w-4" />
                  {tCreate('burnAfterReading')}
                </label>
              )}

              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={passwordProtected}
                    onChange={(event) => setPasswordProtected(event.target.checked)}
                    className="rounded"
                  />
                  <Lock className="h-4 w-4" />
                  {t('password')}
                </label>
                {passwordProtected && (
                  <Input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder={tCreate('enterPassword')}
                    className="h-9 w-full"
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {hasDraft && (
        <div className="border-b bg-blue-50 dark:bg-blue-950">
          <div className="container mx-auto px-4 py-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                <Save className="h-4 w-4" />
                <span>{tCreate('draft.unsavedDraft', { draftAge })}</span>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={loadFromDraft}>
                  {tCreate('draft.restore')}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setHasDraft(false)}>
                  ×
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="container mx-auto px-4 py-4">
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_180px]">
            <div className="space-y-2">
              <Label htmlFor="note-title">{t('title')}</Label>
              <Input
                id="note-title"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                placeholder={t('title')}
                onBlur={saveCurrentDraft}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('format')}</Label>
              {renderFormatSelect(true)}
            </div>
          </div>

          {hasAttachedFiles && (
            <Card>
              <CardHeader className="p-4 pb-2">
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Paperclip className="h-3.5 w-3.5" />
                      {tFiles('attachmentsTitle')}
                    </CardTitle>
                    <CardDescription className="mt-0.5 text-[11px]">
                      {formatFileCount(selectedFiles.length)} · {formatBytes(totalSelectedFileSize)}
                    </CardDescription>
                  </div>

                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 px-2.5 text-xs"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      {tFiles('addMoreFiles')}
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 px-1.5 text-xs"
                      onClick={clearFiles}
                    >
                      {tFiles('removeAllFiles')}
                    </Button>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-2 p-4 pt-1">
                {selectedFiles.map((file, index) => (
                  <div
                    key={`${file.name}-${file.size}-${file.lastModified}-${index}`}
                    className="flex items-center justify-between gap-3 rounded-md border px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium leading-tight">{file.name}</div>
                      <div className="mt-0.5 text-[11px] text-muted-foreground">
                        {formatBytes(file.size)}
                      </div>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 text-muted-foreground"
                      onClick={() => removeFile(index)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}

                {uploadProgress > 0 && (
                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between text-xs">
                      <span>{tFiles('uploadProgress')}</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full bg-primary transition-all"
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {createError && (
            <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700 dark:bg-red-950 dark:text-red-100">
              {createError}
            </div>
          )}

          <Editor
            value={body}
            onChange={setBody}
            language={format}
            height={hasAttachedFiles ? 'calc(100vh - 360px)' : 'calc(100vh - 260px)'}
          />

          <div className="flex justify-end">
            <Button onClick={() => void handleCreate()} disabled={!canSubmit || isCreating} size="lg">
              {isCreating
                ? t('creating')
                : hasAttachedFiles
                  ? tFiles('sendShare')
                  : t('send')}
            </Button>
          </div>
        </div>
      </div>

      <ThemeToggle />
    </div>
  )
}
