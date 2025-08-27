import { Draft } from '@/types'

const DRAFT_KEY = 'pastevault_draft'

export function saveDraft(draft: Omit<Draft, 'saved_at'>): void {
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
    
    const draft = JSON.parse(saved) as Draft
    
    // Check if draft is older than 7 days
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
    if (draft.saved_at < weekAgo) {
      clearDraft()
      return null
    }
    
    return draft
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

export function getDraftAge(draft: Draft): string {
  const now = Date.now()
  const diff = now - draft.saved_at
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  
  if (days > 0) return `${days}d ago`
  if (hours > 0) return `${hours}h ago`
  if (minutes > 0) return `${minutes}m ago`
  return 'just now'
}