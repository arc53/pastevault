import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'
import { I18nProvider } from '@/components/i18n-provider'
import { Footer } from '@/components/footer'

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
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" />
        <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />
        <meta name="theme-color" content="#14161a" media="(prefers-color-scheme: dark)" />


      </head>
      <body className={inter.className}>
        <I18nProvider>
          <Providers>
            <div className="min-h-screen bg-background flex flex-col">
              <main className="flex-1">
                {children}
              </main>
              <Footer />
            </div>
          </Providers>
        </I18nProvider>
      </body>
    </html>
  )
}
