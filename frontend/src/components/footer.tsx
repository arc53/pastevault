'use client'

import { useTranslations } from 'next-intl'
import { LanguageSwitcher } from './language-switcher'

export function Footer() {
  const t = useTranslations('footer')
  
  return (
    <footer className="border-t text-xs text-muted-foreground py-2 px-4 sm:px-6 text-center relative">
      <div className="text-[10px] sm:text-xs pr-16 sm:pr-0">
        {t('projectBy')}{' '}
        <a
          href="https://www.arc53.com/"
          target="_blank"
          rel="noopener noreferrer"
          className="font-medium hover:text-foreground transition-colors"
        >
          Arc53
        </a>
        {' '}• {t('repo')}{' '}
        <a
          href="https://github.com/arc53/pastevault"
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono hover:text-foreground transition-colors"
        >
          github.com/arc53/pastevault
        </a>
      </div>
      <div className="absolute right-4 sm:right-6 top-1/2 transform -translate-y-1/2">
        <LanguageSwitcher />
      </div>
    </footer>
  )
}