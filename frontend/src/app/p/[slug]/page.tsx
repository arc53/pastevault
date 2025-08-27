'use client'

import { useState, useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { MarkdownRenderer } from '@/components/markdown-renderer'
import { useGetPaste } from '@/hooks/usePaste'
import { ThemeToggle } from '@/components/theme-toggle'
import { CopyButton } from '@/components/copy-button'
import { 
  decryptPaste, 
  decryptPasteWithPassword, 
  extractKeyFromFragment 
} from '@/lib/crypto'
import { PasteContent } from '@/types'
import { 
  Lock, 
  Eye, 
  Flame, 
  AlertCircle,
  Loader2,
  Menu,
  X 
} from 'lucide-react'
import Link from 'next/link'

export default function ViewPastePage() {
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
        // Check if it's a zero-knowledge link with key in fragment
        const fragmentKey = extractKeyFromFragment()
        
        if (fragmentKey && !paste.salt) {
          // Zero-knowledge mode
          const keyBytes = new Uint8Array(
            atob(fragmentKey.replace(/-/g, '+').replace(/_/g, '/'))
              .split('')
              .map(c => c.charCodeAt(0))
          )
          
          const decryptedContent = await decryptPaste(
            paste.ciphertext,
            paste.nonce,
            keyBytes,
            paste.metadata.slug
          )
          
          setContent(decryptedContent)
        } else if (paste.salt && paste.kdf_params) {
          // Password-protected mode
          setShowPasswordPrompt(true)
        } else {
          setDecryptionError('Invalid paste format or missing decryption key')
        }
      } catch (error) {
        console.error('Decryption failed:', error)
        setDecryptionError('Failed to decrypt paste. Invalid key or corrupted data.')
      } finally {
        setIsDecrypting(false)
      }
    }

    attemptDecryption()
  }, [paste])

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
    } catch (error) {
      console.error('Password decryption failed:', error)
      setDecryptionError('Incorrect password or corrupted data')
    } finally {
      setIsDecrypting(false)
    }
  }




  const getTimeRemaining = (expiresAt: string | null) => {
    if (!expiresAt) return 'Never expires'
    
    const now = new Date().getTime()
    const expiry = new Date(expiresAt).getTime()
    const diff = expiry - now
    
    if (diff <= 0) return 'Expired'
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    
    if (days > 0) return `${days}d ${hours}h remaining`
    if (hours > 0) return `${hours}h ${minutes}m remaining`
    return `${minutes}m remaining`
  }

  if (isLoading) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-4xl">
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin" />
            <span className="ml-2">Loading paste...</span>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    const errorMessage = (error as Error)?.message || 'Unknown error'
    const isNotFound = (error as { status?: number })?.status === 404
    const isBurned = errorMessage.includes('burned')
    const isExpired = errorMessage.includes('expired')

    return (
      <div className="container mx-auto py-8 px-4 max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="flex items-center gap-2 justify-center text-red-600">
              <AlertCircle className="h-5 w-5" />
              {isNotFound ? 'Paste Not Found' : 
               isBurned ? 'Paste Burned' : 
               isExpired ? 'Paste Expired' : 'Error'}
            </CardTitle>
            <CardDescription>
              {isNotFound && 'The paste you\'re looking for doesn\'t exist or has been deleted.'}
              {isBurned && 'This paste was set to burn after reading and has already been viewed.'}
              {isExpired && 'This paste has expired and is no longer available.'}
              {!isNotFound && !isBurned && !isExpired && errorMessage}
            </CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Link href="/">
              <Button>Create New Paste</Button>
            </Link>
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
              Password Protected
            </CardTitle>
            <CardDescription>
              This paste is password protected. Enter the password to decrypt and view the content.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password..."
                onKeyPress={(e) => {
                  if (e.key === 'Enter' && password) {
                    handlePasswordDecrypt()
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
              onClick={handlePasswordDecrypt}
              disabled={!password || isDecrypting}
              className="w-full"
            >
              {isDecrypting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Decrypting...
                </>
              ) : (
                'Decrypt Paste'
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
            <span className="ml-2">Decrypting paste...</span>
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
              Decryption Failed
            </CardTitle>
            <CardDescription>{decryptionError}</CardDescription>
          </CardHeader>
          <CardContent className="text-center">
            <Button onClick={() => router.push('/')}>
              Create New Paste
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!content || !paste) {
    return null
  }

  // Prepare markdown for rendering based on paste mode
  const toFencedMarkdown = (body: string, lang?: string) => {
    const useTilde = body.includes('```')
    const fence = useTilde ? '~~~~' : '```'
    const langId = lang ? lang : ''
    return `${fence}${langId}\n${body}\n${fence}`
  }
  const renderedBody = content.render_mode === 'plain'
    ? toFencedMarkdown(content.body, content.language_hint)
    : content.body

  return (
    <div>
      {/* Top toolbar */}
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <Link href="/">
              <h1 className="text-xl font-semibold cursor-pointer">PasteVault</h1>
            </Link>
            
            <div className="flex items-center gap-2">
              <div className="hidden md:flex items-center gap-4">
                <CopyButton
                  getValue={() => content?.body ?? ''}
                  variant="outline"
                  size="sm"
                  label="Copy Content"
                />
                <CopyButton
                  getValue={() => window.location.href}
                  variant="outline"
                  size="sm"
                  label="Copy URL"
                />
                <Link href="/">
                  <Button size="sm">
                    Create New
                  </Button>
                </Link>
              </div>
              <button
                className="md:hidden inline-flex items-center justify-center rounded-md p-2 hover:bg-muted"
                aria-controls="mobile-menu"
                aria-expanded={mobileMenuOpen}
                aria-label="Open menu"
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
              <h2 className="text-lg font-semibold">Options</h2>
              <button
                className="inline-flex items-center justify-center rounded-md p-2 hover:bg-muted"
                aria-label="Close menu"
                onClick={() => setMobileMenuOpen(false)}
              >
                <X className="h-6 w-6" />
              </button>
            </div>
            <div className="space-y-3">
              <CopyButton
                getValue={() => content?.body ?? ''}
                variant="outline"
                size="sm"
                label="Copy Content"
              />
              <CopyButton
                getValue={() => window.location.href}
                variant="outline"
                size="sm"
                label="Copy URL"
              />
              <Link href="/">
                <Button className="w-full">
                  Create New
                </Button>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="container mx-auto px-4 py-6">
        <div className="space-y-4">
          <div className="border rounded-md overflow-hidden bg-white dark:bg-[#1A1F26] dark:border-[#2F353D]">
            {((content.title?.trim() && content.title.trim() !== 'Untitled') || content.language_hint) && (
              <div className="border-b bg-muted/50 px-4 py-2">
                {(content.title?.trim() && content.title.trim() !== 'Untitled') && (
                  <div className="font-medium">{content.title}</div>
                )}
                {content.language_hint && (
                  <div className="text-sm text-muted-foreground">
                    {content.language_hint}
                  </div>
                )}
              </div>
            )}
            <div className="p-0">
              <MarkdownRenderer 
                content={renderedBody} 
                className="min-h-[400px] p-4"
              />
            </div>
          </div>

          {/* Bottom stats bar */}
          <div className="flex items-center justify-between text-sm text-muted-foreground bg-muted/30 px-4 py-2 rounded-md">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Eye className="h-3 w-3" />
                {paste.metadata.view_count} views
              </div>
              <div className="flex items-center gap-2">
                <Lock className="h-3 w-3" />
                {paste.salt ? 'Password protected' : 'Zero-knowledge'}
              </div>
              {paste.metadata.burn_after_read && (
                <div className="flex items-center gap-2 text-orange-600">
                  <Flame className="h-3 w-3" />
                  Burns after reading
                </div>
              )}
            </div>
            <div>
              {paste.metadata.expires_at ? (
                <span className="text-amber-600">{getTimeRemaining(paste.metadata.expires_at)}</span>
              ) : (
                'Never expires'
              )}
            </div>
          </div>
        </div>
      </div>
      <ThemeToggle />
    </div>
  )
}
