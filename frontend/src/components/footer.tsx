'use client'

import { useTranslations } from 'next-intl'
import { LanguageSwitcher } from './language-switcher'

export function Footer() {
  const t = useTranslations('footer')
  
  return (
    <footer className="border-t border-border/80 bg-background/70 backdrop-blur-md">
      <div className="app-frame flex flex-col gap-3 py-3 text-[11px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span className="tool-label">{t('projectBy')}</span>
          <a
            href="https://www.arc53.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-foreground/85 hover:text-foreground"
          >
            Arc53
          </a>
          <span className="tool-label">{t('repo')}</span>
          <a
            href="https://github.com/arc53/pastevault"
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono text-foreground/85 hover:text-foreground"
          >
            github.com/arc53/pastevault
          </a>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className="tool-label">locale</span>
          <LanguageSwitcher />
        </div>
      </div>
    </footer>
  )
}
