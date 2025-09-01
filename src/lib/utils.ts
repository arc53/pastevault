const { nanoid } = require('nanoid')

export function generateSlug(): string {
  return nanoid(12)
}

export function calculateExpiryDate(hoursFromNow: number): Date {
  return new Date(Date.now() + hoursFromNow * 60 * 60 * 1000)
}

export function isExpired(expiresAt: Date | null): boolean {
  if (!expiresAt) return false
  return new Date() > expiresAt
}
