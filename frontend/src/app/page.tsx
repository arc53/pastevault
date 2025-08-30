'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useTranslations } from 'next-intl'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Editor } from '@/components/editor'
import { ThemeToggle } from '@/components/theme-toggle'
import { CopyButton } from '@/components/copy-button'
import { useCreatePaste } from '@/hooks/usePaste'
import { encryptPaste, encryptPasteWithPassword, createShareUrl } from '@/lib/crypto'
import { saveDraft, loadDraft, clearDraft, getDraftAge } from '@/lib/drafts'
import { PasteContent } from '@/types'
import { Lock, Save, Share, Flame, AlertCircle, Menu, X } from 'lucide-react'
import { nanoid } from 'nanoid'

export default function CreatePastePage() {
  const t = useTranslations('common')
  const tCreate = useTranslations('createPaste')
  const tExpiration = useTranslations('expiration')
  const tFormats = useTranslations('formats')
  const tShare = useTranslations('shareSuccess')
  const tAccessibility = useTranslations('accessibility')
  
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [format, setFormat] = useState('markdown')
  const [expiresInHours, setExpiresInHours] = useState(24)
  const [burnAfterRead, setBurnAfterRead] = useState(false)
  const [passwordProtected, setPasswordProtected] = useState(false)
  const [password, setPassword] = useState('')
  const [shareUrl, setShareUrl] = useState('')
  const [isCreating, setIsCreating] = useState(false)
  const [hasDraft, setHasDraft] = useState(false)
  const [draftAge, setDraftAge] = useState('')

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const router = useRouter()
  const createPaste = useCreatePaste()

  useEffect(() => {
    const draft = loadDraft()
    if (draft) {
      setHasDraft(true)
      setDraftAge(getDraftAge(draft))
    }
  }, [])

  const loadFromDraft = () => {
    const draft = loadDraft()
    if (draft) {
      setTitle(draft.title)
      setBody(draft.body)
      setFormat(draft.language_hint || 'markdown')
      setExpiresInHours(draft.expires_in_hours || 24)
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
      })
    }
  }

  const handleCreatePaste = async () => {
    if (!body.trim()) return

    setIsCreating(true)
    try {
      const content: PasteContent = {
        title: title.trim() || '',
        body,
        render_mode: format === 'markdown' || format === 'plain' ? format as 'markdown' | 'plain' : 'plain',
        language_hint: format !== 'markdown' && format !== 'plain' ? format : undefined,
      }

      // Generate slug client-side for consistent AAD
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

      const url = createShareUrl(
        response.slug,
        'key' in encryptionResult ? encryptionResult.key : undefined
      )
      setShareUrl(url)
      clearDraft()
    } catch (error) {
      console.error('Failed to create paste:', error)
    } finally {
      setIsCreating(false)
    }
  }


  const createNew = () => {
    setTitle('')
    setBody('')
    setFormat('markdown')
    setPassword('')
    setShareUrl('')
    setPasswordProtected(false)
    clearDraft()
  }

  // Close mobile menu on Escape and lock body scroll when open
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileMenuOpen(false)
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

  if (shareUrl) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center gap-2 justify-center">
              <Share className="h-5 w-5" />
              {tShare('title')}
            </CardTitle>
            <CardDescription>
              {tShare('description')}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>{tShare('shareUrl')}</Label>
              <div className="flex gap-2">
                <Input
                  value={shareUrl}
                  readOnly
                  className="font-mono text-sm"
                />
                <CopyButton value={shareUrl} variant="outline" />
              </div>
            </div>
            
            <div className="bg-muted/50 p-4 rounded-lg">
              <div className="flex items-start gap-2">
                <AlertCircle className="h-4 w-4 text-amber-500 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium">{tShare('important')}</p>
                  <p className="text-muted-foreground mt-1">
                    {passwordProtected 
                      ? tShare('passwordProtectedWarning')
                      : tShare('urlWarning')
                    }
                  </p>
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <Button onClick={createNew} className="flex-1">
                {tShare('createAnother')}
              </Button>
              <Button onClick={() => router.push(shareUrl)} variant="outline">
                {tShare('viewPaste')}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div>
      {/* Top toolbar */}
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <h1 className="text-xl font-semibold">{t('pasteVault')}</h1>
            
            <div className="flex items-center gap-2">
              <div className="hidden md:flex items-center gap-4">
              {/* Expiration dropdown */}
              <Select value={expiresInHours.toString()} onValueChange={(value) => setExpiresInHours(Number(value))}>
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

              {/* Burn after read */}
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={burnAfterRead}
                  onChange={(e) => setBurnAfterRead(e.target.checked)}
                  className="rounded"
                />
                <Flame className="h-4 w-4" />
                {tCreate('burnAfterReading')}
              </label>

              {/* Password protection */}
              <div className="flex items-center gap-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={passwordProtected}
                    onChange={(e) => setPasswordProtected(e.target.checked)}
                    className="rounded"
                  />
                  <Lock className="h-4 w-4" />
                  {t('password')}
                </label>
                {passwordProtected && (
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={tCreate('enterPassword')}
                    className="w-32 h-9"
                  />
                )}
              </div>

              {/* Title input */}
              <Input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={t('title')}
                className="w-32 h-9"
                onBlur={saveCurrentDraft}
              />

              {/* Format dropdown */}
              <Select value={format} onValueChange={setFormat}>
                <SelectTrigger className="w-[140px]">
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
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{tCreate('expiresIn')}</Label>
                <Select value={expiresInHours.toString()} onValueChange={(value) => setExpiresInHours(Number(value))}>
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

              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={burnAfterRead}
                  onChange={(e) => setBurnAfterRead(e.target.checked)}
                  className="rounded"
                />
                <Flame className="h-4 w-4" />
                {tCreate('burnAfterReading')}
              </label>

              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={passwordProtected}
                    onChange={(e) => setPasswordProtected(e.target.checked)}
                    className="rounded"
                  />
                  <Lock className="h-4 w-4" />
                  {t('password')}
                </label>
                {passwordProtected && (
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={tCreate('enterPassword')}
                    className="w-full h-9"
                  />
                )}
              </div>

              <div className="space-y-2">
                <Label>{t('title')}</Label>
                <Input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder={t('title')}
                  className="w-full h-9"
                  onBlur={saveCurrentDraft}
                />
              </div>

              <div className="space-y-2">
                <Label>{t('format')}</Label>
                <Select value={format} onValueChange={setFormat}>
                  <SelectTrigger className="w-full">
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
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Draft restore notification */}
      {hasDraft && (
        <div className="bg-blue-50 dark:bg-blue-950 border-b">
          <div className="container mx-auto px-4 py-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                <Save className="h-4 w-4" />
                <span>{tCreate('draft.unsavedDraft', {draftAge})}</span>
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

      {/* Main editor */}
      <div className="container mx-auto px-4 py-4">
        <div className="space-y-4">
          <Editor
            value={body}
            onChange={setBody}
            language={format}
            height="calc(100vh - 200px)"
            placeholder={format === 'markdown' 
              ? tCreate('welcomePlaceholder')
              : tCreate('plainPlaceholder')
            }
          />
          
          <div className="flex justify-end">
            <Button
              onClick={handleCreatePaste}
              disabled={!body.trim() || isCreating || (passwordProtected && !password)}
              size="lg"
            >
              {isCreating ? t('creating') : t('send')}
            </Button>
          </div>
        </div>
      </div>
      <ThemeToggle />
    </div>
  )
}
