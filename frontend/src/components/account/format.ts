'use client'

import { useMemo } from 'react'
import { useTranslations } from 'next-intl'
import { useLocale } from '@/components/i18n-provider'
import { AuditEvent } from '@/types'

const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 365 * 24 * 60 * 60],
  ['month', 30 * 24 * 60 * 60],
  ['week', 7 * 24 * 60 * 60],
  ['day', 24 * 60 * 60],
  ['hour', 60 * 60],
  ['minute', 60],
]

// Locale-aware date helpers for the account cards.
export function useDateFormat() {
  const { locale } = useLocale()

  return useMemo(() => {
    const dateTime = new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' })
    const date = new Intl.DateTimeFormat(locale, { dateStyle: 'medium' })
    const relative = new Intl.RelativeTimeFormat(locale, { numeric: 'auto', style: 'short' })

    return {
      dateTime: (value: string) => dateTime.format(new Date(value)),
      date: (value: string) => date.format(new Date(value)),
      // "5 min. ago", "in 3 days"; "now" under a minute.
      relative: (value: string) => {
        const seconds = (new Date(value).getTime() - Date.now()) / 1000
        for (const [unit, size] of RELATIVE_UNITS) {
          if (Math.abs(seconds) >= size) {
            return relative.format(Math.round(seconds / size), unit)
          }
        }
        return relative.format(0, 'second')
      },
    }
  }, [locale])
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value ? value : null
}

// Human text for one audit event: what happened, a short detail, and who did
// it from which client. Unknown events (from a newer server) fall back to the
// raw event name.
export function useAuditEventText() {
  const t = useTranslations('account.audit')

  return (event: AuditEvent) => {
    const eventKey = `events.${event.event}`
    const label = t.has(eventKey) ? t(eventKey) : event.event
    const details = event.details ?? {}

    let detail: string | null = null
    switch (event.event) {
      case 'share.viewed': {
        const view = asNumber(details.view)
        const maxViews = asNumber(details.max_views)
        const views = asNumber(details.views)
        if (view !== null && maxViews !== null) {
          detail = t('detail.viewOf', { view, max: maxViews })
        } else if (views !== null && views > 1) {
          detail = t('detail.views', { count: views })
        }
        break
      }
      case 'share.access_denied': {
        const reason = asString(details.reason)
        const attempts = asNumber(details.attempts)
        const reasonKey = `denyReasons.${reason}`
        const reasonText = reason ? (t.has(reasonKey) ? t(reasonKey) : reason) : null
        detail = [reasonText, attempts && attempts > 1 ? t('detail.attempts', { count: attempts }) : null]
          .filter(Boolean)
          .join(' · ') || null
        break
      }
      case 'token.created':
      case 'token.revoked': {
        const name = asString(details.name)
        const prefix = asString(details.prefix)
        detail = [name, prefix ? `${prefix}…` : null].filter(Boolean).join(' · ') || null
        if (details.reason === 'agent_revoked') {
          detail = [detail, t('detail.agentRevoked')].filter(Boolean).join(' · ')
        }
        break
      }
      case 'agent.registered':
      case 'agent.revoked':
        detail = asString(details.name)
        break
    }

    const agentName = event.actor_agent?.name ?? null
    let actor: string
    switch (event.actor_kind) {
      case 'owner':
        actor = agentName ? t('actor.ownerAgent', { name: agentName }) : t('actor.owner')
        break
      case 'recipient':
        actor = t('actor.recipient', { name: agentName ?? '?' })
        break
      case 'system':
        actor = t('actor.system')
        break
      default:
        actor = t('actor.anonymous')
    }

    const client =
      event.client === 'browser'
        ? t('client.browser')
        : event.client === 'other'
          ? t('client.other')
          : event.client

    return { label, detail, actor, client }
  }
}
