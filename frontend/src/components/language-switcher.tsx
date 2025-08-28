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
      <SelectTrigger className="w-[50px] h-6 text-xs border-none bg-transparent hover:bg-muted/50 p-1 text-muted-foreground hover:text-foreground transition-colors">
        <SelectValue>
          <span>
            {currentLanguage?.code.toUpperCase()}
          </span>
        </SelectValue>
      </SelectTrigger>
      <SelectContent align="end" className="min-w-[100px]">
        {languages.map((language) => (
          <SelectItem key={language.code} value={language.code} className="text-xs">
            {language.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}