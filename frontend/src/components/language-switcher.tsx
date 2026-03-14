'use client'

import { useLocale } from '@/components/i18n-provider'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Locale } from '@/lib/i18n'

const languages = [
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Español' },
  { code: 'zh', name: '中文' },
  { code: 'ru', name: 'Русский' },
  { code: 'ja', name: '日本語' },
] as const

export function LanguageSwitcher() {
  const { locale, setLocale } = useLocale()

  const handleLanguageChange = (newLocale: string) => {
    setLocale(newLocale as Locale)
  }

  const currentLanguage = languages.find(lang => lang.code === locale)

  return (
    <Select value={locale} onValueChange={handleLanguageChange}>
      <SelectTrigger className="h-8 w-[68px] border-border/70 bg-background/55 px-2 py-0 text-[11px] text-muted-foreground hover:text-foreground">
        <SelectValue>
          <span>
            {currentLanguage?.code.toUpperCase()}
          </span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent align="end" className="min-w-[120px]">
        {languages.map((language) => (
          <SelectItem key={language.code} value={language.code} className="text-xs">
            {language.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
