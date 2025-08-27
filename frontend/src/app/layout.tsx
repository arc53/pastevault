import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'PasteVault - Secure Encrypted Paste Sharing',
  description: 'Share code, text, and markdown securely with end-to-end encryption. Zero-knowledge paste sharing with expiry and burn-after-read options.',
  keywords: ['paste', 'pastebin', 'encrypted', 'secure', 'code sharing', 'markdown'],
  authors: [{ name: 'PasteVault' }],
  openGraph: {
    title: 'PasteVault - Secure Encrypted Paste Sharing',
    description: 'Share code, text, and markdown securely with end-to-end encryption.',
    type: 'website',
  },
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: [
      { url: '/favicon/favicon.ico', sizes: 'any' },
      { url: '/favicon/favicon.svg', type: 'image/svg+xml' },
    ],
    apple: '/favicon/apple-touch-icon.png',
  },
  manifest: '/favicon/site.webmanifest',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <Providers>
          <div className="min-h-screen bg-background flex flex-col">
            <main className="flex-1">
              {children}
            </main>
            <footer className="border-t text-xs text-muted-foreground py-2 px-4 sm:px-6 text-center">
              Project by{' '}
              <a
                href="https://www.arc53.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium hover:text-foreground transition-colors"
              >
                Arc53
              </a>
              {' '}• Repo:{' '}
              <a
                href="https://github.com/arc53/pastevault"
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono hover:text-foreground transition-colors"
              >
                github.com/arc53/pastevault
              </a>
            </footer>
          </div>
        </Providers>
      </body>
    </html>
  )
}
