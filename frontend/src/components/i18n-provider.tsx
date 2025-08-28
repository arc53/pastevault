'use client'

import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { NextIntlClientProvider } from 'next-intl'
import { Locale, getBrowserLocale, setLocale as setStoredLocale, getMessages } from '@/lib/i18n'

interface I18nContextType {
  locale: Locale
  setLocale: (locale: Locale) => void
  messages: Record<string, any>
  isLoading: boolean
}

const I18nContext = createContext<I18nContextType | undefined>(undefined)

export function useLocale() {
  const context = useContext(I18nContext)
  if (!context) {
    throw new Error('useLocale must be used within I18nProvider')
  }
  return context
}

interface I18nProviderProps {
  children: ReactNode
}

export function I18nProvider({ children }: I18nProviderProps) {
  const [locale, setCurrentLocale] = useState<Locale>('en')
  const [messages, setMessages] = useState<Record<string, any>>({})
  const [isLoading, setIsLoading] = useState(true)

  // Load messages for a specific locale
  const loadMessages = async (newLocale: Locale) => {
    setIsLoading(true)
    try {
      const newMessages = await getMessages(newLocale)
      setMessages(newMessages)
      setCurrentLocale(newLocale)
    } catch (error) {
      console.error('Failed to load messages for locale:', newLocale, error)
      // Fallback to English
      if (newLocale !== 'en') {
        const fallbackMessages = await getMessages('en')
        setMessages(fallbackMessages)
        setCurrentLocale('en')
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Set locale and persist to localStorage
  const setLocale = (newLocale: Locale) => {
    setStoredLocale(newLocale)
    loadMessages(newLocale)
  }

  // Initialize locale on mount
  useEffect(() => {
    const initialLocale = getBrowserLocale()
    loadMessages(initialLocale)
  }, [])

  const contextValue = {
    locale,
    setLocale,
    messages,
    isLoading
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  return (
    <I18nContext.Provider value={contextValue}>
      <NextIntlClientProvider locale={locale} messages={messages}>
        {children}
      </NextIntlClientProvider>
    </I18nContext.Provider>
  )
}