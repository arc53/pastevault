'use client'

import { DragEvent, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslations } from 'next-intl'
import { Eye, EyeOff, FileUp, Loader2, Lock, Trash2 } from 'lucide-react'
import { ApiError, api } from '@/lib/api'
import { formatBytes } from '@/lib/file-shares'
import { filePayload, maxFileBytes, sealedSize, sealSecretPayload, textPayload } from '@/lib/secret-requests'
import { cn } from '@/lib/utils'
import { SecretRequestDetails } from '@/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ConfirmButton } from '@/components/account/confirm-button'

type Mode = 'text' | 'file'

// Text from a textarea loses one trailing newline, like the CLI's
// --from-file/--from-stdin, so a pasted "sk-…\n" isn't sent with the break.
function normaliseText(value: string) {
  return value.replace(/\r?\n$/, '')
}

interface AnswerFormProps {
  request: SecretRequestDetails
  requestPublicKey: Uint8Array
  // Submitting is blocked (key mismatch, expired).
  blocked: boolean
  onSent: () => void
  onDeclined: () => void
  onStale: () => void
}

// The secret only lives in this component's state: never in drafts or
// storage, and cleared as soon as it is sealed and sent.
export function AnswerForm({ request, requestPublicKey, blocked, onSent, onDeclined, onStale }: AnswerFormProps) {
  const t = useTranslations('secretRequest.answer')
  const [mode, setMode] = useState<Mode>(request.accept === 'file' ? 'file' : 'text')
  const [text, setText] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [declining, setDeclining] = useState(false)
  const [error, setError] = useState('')
  const [canMask, setCanMask] = useState(true)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    // Firefox lacks -webkit-text-security: there the hidden state uses a
    // password input instead (single line; "Show" for multi-line values).
    setCanMask(typeof CSS !== 'undefined' && CSS.supports('-webkit-text-security', 'disc'))
  }, [])

  const textSize = useMemo(
    () => (mode === 'text' ? sealedSize(textPayload(request.name, normaliseText(text))) : 0),
    [mode, request.name, text]
  )
  const fileLimit = maxFileBytes(request.max_bytes, request.name, file?.name ?? 'file', file?.type ?? '')
  const tooLarge = mode === 'text' ? textSize > request.max_bytes : Boolean(file && file.size > fileLimit)
  const empty = mode === 'text' ? !normaliseText(text).trim() : !file

  const chooseFile = (files: FileList | null) => {
    const next = files?.[0]
    setError('')
    setFile(next ?? null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragging(false)
    if (!busy && !blocked) {
      chooseFile(event.dataTransfer.files)
    }
  }

  const handleSubmit = async () => {
    if (blocked || empty || tooLarge) {
      return
    }

    setBusy(true)
    setError('')
    try {
      const payload =
        mode === 'text'
          ? textPayload(request.name, normaliseText(text))
          : filePayload(request.name, file!.name, file!.type, new Uint8Array(await file!.arrayBuffer()))
      if (sealedSize(payload) > request.max_bytes) {
        setError(t('tooLarge', { size: formatBytes(request.max_bytes) }))
        return
      }
      const sealed = sealSecretPayload(payload, request.id, requestPublicKey)
      await api.fulfillSecretRequest(request.id, sealed)
      setText('')
      setFile(null)
      setRevealed(false)
      onSent()
    } catch (submitError) {
      const apiError = submitError instanceof ApiError ? submitError : null
      if (apiError?.status === 409 || apiError?.status === 410 || apiError?.status === 404) {
        // Answered, declined, cancelled or expired meanwhile: show that state.
        setText('')
        setFile(null)
        onStale()
      } else if (apiError?.status === 413) {
        setError(t('tooLarge', { size: formatBytes(request.max_bytes) }))
      } else {
        setError((submitError as Error).message || t('failed'))
      }
    } finally {
      setBusy(false)
    }
  }

  const handleDecline = async () => {
    setDeclining(true)
    setError('')
    try {
      await api.declineSecretRequest(request.id)
      setText('')
      setFile(null)
      onDeclined()
    } catch (declineError) {
      const apiError = declineError instanceof ApiError ? declineError : null
      if (apiError && [404, 409, 410].includes(apiError.status)) {
        onStale()
      } else {
        setError((declineError as Error).message || t('failed'))
      }
    } finally {
      setDeclining(false)
    }
  }

  const disabled = busy || declining || blocked
  const masked = !revealed

  return (
    <div className="space-y-4" data-testid="answer-form">
      {request.accept === 'any' && (
        <div className="inline-flex rounded-sm border border-border/80 p-0.5" role="group" aria-label={t('kindLabel')}>
          {(['text', 'file'] as const).map((value) => (
            <Button
              key={value}
              type="button"
              size="sm"
              variant={mode === value ? 'secondary' : 'ghost'}
              aria-pressed={mode === value}
              disabled={disabled}
              onClick={() => {
                setMode(value)
                setError('')
              }}
            >
              {value === 'text' ? t('kindText') : t('kindFile')}
            </Button>
          ))}
        </div>
      )}

      {mode === 'text' ? (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <Label htmlFor="secret-value">{t('valueLabel', { name: request.name })}</Label>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7"
              aria-pressed={revealed}
              aria-controls="secret-value"
              onClick={() => setRevealed((value) => !value)}
            >
              {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              {revealed ? t('hide') : t('show')}
            </Button>
          </div>
          {masked && !canMask ? (
            <Input
              id="secret-value"
              type="password"
              value={text}
              disabled={disabled}
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
              placeholder={t('valuePlaceholder')}
              onChange={(event) => setText(event.target.value)}
              className="font-mono"
              data-testid="secret-value"
            />
          ) : (
            <textarea
              id="secret-value"
              value={text}
              disabled={disabled}
              rows={4}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              data-1p-ignore
              data-lpignore="true"
              placeholder={t('valuePlaceholder')}
              onChange={(event) => setText(event.target.value)}
              style={masked ? ({ WebkitTextSecurity: 'disc' } as React.CSSProperties) : undefined}
              className="block w-full resize-y rounded-sm border border-input bg-background/75 px-3 py-2 font-mono text-[13px] shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] placeholder:text-muted-foreground/85 focus-visible:border-ring focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="secret-value"
            />
          )}
          {tooLarge && (
            <p className="text-xs text-red-700 dark:text-red-300" role="alert">
              {t('tooLarge', { size: formatBytes(request.max_bytes) })}
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          <Label htmlFor="secret-file">{t('fileLabel', { name: request.name })}</Label>
          <input
            ref={fileInputRef}
            id="secret-file"
            type="file"
            className="sr-only"
            tabIndex={-1}
            disabled={disabled}
            onChange={(event) => chooseFile(event.target.files)}
            data-testid="secret-file"
          />
          {file ? (
            <div className="flex items-center justify-between gap-3 rounded-sm border border-border/70 bg-background/55 px-3 py-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{file.name}</p>
                <p className={cn('text-[11px]', tooLarge ? 'text-red-700 dark:text-red-300' : 'text-muted-foreground')}>
                  {tooLarge ? t('fileTooLarge', { size: formatBytes(fileLimit) }) : formatBytes(file.size)}
                </p>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0 text-muted-foreground"
                aria-label={t('removeFile')}
                disabled={disabled}
                onClick={() => setFile(null)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          ) : (
            <div
              className={cn(
                'flex flex-col items-center gap-2 rounded-sm border border-dashed border-border px-4 py-6 text-center text-sm text-muted-foreground transition-colors',
                dragging && 'border-primary bg-primary/5 text-foreground'
              )}
              onDragOver={(event) => {
                event.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={handleDrop}
            >
              <FileUp className="h-5 w-5" />
              <p>{t('dropHint')}</p>
              <Button type="button" variant="outline" size="sm" disabled={disabled} onClick={() => fileInputRef.current?.click()}>
                {t('chooseFile')}
              </Button>
              <p className="text-[11px]">{t('fileLimit', { size: formatBytes(fileLimit) })}</p>
            </div>
          )}
        </div>
      )}

      {error && (
        <p className="rounded-sm border border-red-500/25 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-200" role="alert">
          {error}
        </p>
      )}

      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:items-center sm:justify-between">
        <ConfirmButton
          label={t('decline')}
          confirmLabel={t('confirmDecline')}
          busy={declining}
          disabled={busy}
          onConfirm={handleDecline}
        />
        <Button
          type="button"
          disabled={disabled || empty || tooLarge}
          onClick={() => void handleSubmit()}
          data-testid="submit-secret"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
          {busy ? t('sending') : t('send')}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('e2eNote')}</p>
    </div>
  )
}
