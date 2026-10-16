import { Draft } from '@/types'

const DRAFT_KEY = 'pastevault_draft'
const DRAFT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

export type DraftContent = Omit<Draft, 'saved_at'>

export function isDraftEmpty(draft: DraftContent): boolean {
  return !draft.title && !draft.body
}

// Stable string form of a draft, used to skip redundant writes.
export function serializeDraft(draft: DraftContent): string {
  return JSON.stringify([
    draft.title,
    draft.body,
    draft.language_hint ?? null,
    draft.expires_in_hours ?? null,
    draft.burn_after_read,
    draft.password_protected,
  ])
}

export function saveDraft(draft: DraftContent): void {
  const draftWithTimestamp: Draft = {
    ...draft,
    saved_at: Date.now(),
  }

  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(draftWithTimestamp))
  } catch (error) {
    console.warn('Failed to save draft:', error)
  }
}

export function loadDraft(): Draft | null {
  try {
    const saved = localStorage.getItem(DRAFT_KEY)
    if (!saved) return null

    const parsed: unknown = JSON.parse(saved)
    if (!parsed || typeof parsed !== 'object') {
      clearDraft()
      return null
    }

    const raw = parsed as Partial<Record<keyof Draft, unknown>>
    if (
      typeof raw.title !== 'string' ||
      typeof raw.body !== 'string' ||
      typeof raw.saved_at !== 'number' ||
      raw.saved_at < Date.now() - DRAFT_MAX_AGE_MS
    ) {
      clearDraft()
      return null
    }

    return {
      title: raw.title,
      body: raw.body,
      language_hint: typeof raw.language_hint === 'string' ? raw.language_hint : undefined,
      expires_in_hours:
        typeof raw.expires_in_hours === 'number' ? raw.expires_in_hours : undefined,
      burn_after_read: raw.burn_after_read === true,
      password_protected: raw.password_protected === true,
      saved_at: raw.saved_at,
    }
  } catch (error) {
    console.warn('Failed to load draft:', error)
    return null
  }
}

export function clearDraft(): void {
  try {
    localStorage.removeItem(DRAFT_KEY)
  } catch (error) {
    console.warn('Failed to clear draft:', error)
  }
}

export function formatDraftAge(savedAt: number, locale: string): string {
  const seconds = Math.round((savedAt - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })

  if (seconds > -60) return formatter.format(seconds, 'second')
  const minutes = Math.round(seconds / 60)
  if (minutes > -60) return formatter.format(minutes, 'minute')
  const hours = Math.round(minutes / 60)
  if (hours > -24) return formatter.format(hours, 'hour')
  return formatter.format(Math.round(hours / 24), 'day')
}
