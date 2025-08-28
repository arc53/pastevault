// Simple i18n implementation with localStorage support
export const locales = ['en', 'es', 'zh', 'ru', 'ja'] as const
export type Locale = typeof locales[number]

export function getBrowserLocale(): Locale {
  if (typeof window === 'undefined') return 'en'
  
  const stored = localStorage.getItem('locale')
  if (stored && locales.includes(stored as Locale)) {
    return stored as Locale
  }
  
  // Check browser preferences
  const browserLang = navigator.language.split('-')[0]
  if (locales.includes(browserLang as Locale)) {
    return browserLang as Locale
  }
  
  return 'en'
}

export function setLocale(locale: Locale) {
  if (typeof window !== 'undefined') {
    localStorage.setItem('locale', locale)
  }
}

export async function getMessages(locale: Locale) {
  const messages = await import(`../../messages/${locale}.json`)
  return messages.default
}