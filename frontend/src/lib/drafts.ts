import { nanoid } from 'nanoid'
import { Draft } from '@/types'

const DRAFT_KEY = 'pastevault_draft'
const DRAFT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

export type DraftContent = Omit<Draft, 'saved_at' | 'id'>

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

// Returns the id of the stored write, or null if it could not be saved.
export function saveDraft(draft: DraftContent): string | null {
  const storedDraft: Draft = {
    ...draft,
    saved_at: Date.now(),
    id: nanoid(12),
  }

  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify(storedDraft))
    return storedDraft.id
  } catch (error) {
    console.warn('Failed to save draft:', error)
    return null
  }
}

export function loadDraft(): Draft | null {
  try {
    const saved = localStorage.getItem(DRAFT_KEY)
    if (!saved) return null

    const parsed: unknown = JSON.parse(saved)
    if (!parsed || typeof parsed !== 'object') {
      removeDraft()
      return null
    }

    const raw = parsed as Partial<Record<keyof Draft, unknown>>
    if (
      typeof raw.title !== 'string' ||
      typeof raw.body !== 'string' ||
      typeof raw.saved_at !== 'number' ||
      raw.saved_at < Date.now() - DRAFT_MAX_AGE_MS
    ) {
      removeDraft()
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
      // Drafts from older builds have no id; their timestamp identifies the write.
      id: typeof raw.id === 'string' ? raw.id : String(raw.saved_at),
    }
  } catch (error) {
    console.warn('Failed to load draft:', error)
    return null
  }
}

// Clears the stored draft only if it is still the write identified by `id`.
export function clearDraft(id: string): void {
  if (loadDraft()?.id === id) {
    removeDraft()
  }
}

function removeDraft(): void {
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
