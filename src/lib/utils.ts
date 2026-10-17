import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { nanoid } from 'nanoid'

export function generateSlug(): string {
  return nanoid(12)
}

export function calculateExpiryDate(hoursFromNow: number): Date {
  return new Date(Date.now() + hoursFromNow * 60 * 60 * 1000)
}

// expires_in_minutes and expires_in_hours are mutually exclusive (validated).
export function resolveShareExpiry(input: {
  expires_in_hours?: number
  expires_in_minutes?: number
}): Date | null {
  if (input.expires_in_minutes !== undefined) {
    return new Date(Date.now() + input.expires_in_minutes * 60 * 1000)
  }

  return input.expires_in_hours !== undefined
    ? calculateExpiryDate(input.expires_in_hours)
    : null
}

// burn_after_read is max_views 1. A share sealed to a recipient defaults to a
// single view. Returns null for unlimited views.
export function resolveMaxViews(input: {
  burn_after_read: boolean
  max_views?: number
  recipient?: unknown
}): number | null {
  if (input.max_views !== undefined) {
    return input.max_views
  }

  return input.burn_after_read || input.recipient ? 1 : null
}

// Rows created before max_views existed only carry burn_after_read.
export function effectiveMaxViews(share: {
  max_views: number | null
  burn_after_read: boolean
}): number | null {
  return share.max_views ?? (share.burn_after_read ? 1 : null)
}

export function viewsRemaining(maxViews: number | null, viewCount: number) {
  return maxViews === null ? null : Math.max(maxViews - viewCount, 0)
}

export function isExpired(expiresAt: Date | null): boolean {
  if (!expiresAt) return false
  return new Date() > expiresAt
}

// Bearer-style secrets (upload tokens, download grants). Only the SHA-256 hash is stored.
export function generateSecretToken(): string {
  return randomBytes(32).toString('base64url')
}

export function hashSecretToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export function secretTokenMatches(
  token: string | undefined,
  expectedHash: string | null
): boolean {
  if (!token || !expectedHash) {
    return false
  }

  const actual = Buffer.from(hashSecretToken(token), 'hex')
  const expected = Buffer.from(expectedHash, 'hex')

  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

export function readHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const value = headers[name.toLowerCase()]
  const first = Array.isArray(value) ? value[0] : value
  return first?.trim() || undefined
}

// Prisma surfaces unique violations as P2002 for model queries; raw queries
// through driver adapters only carry the database error, so match that too.
export function isUniqueConstraintError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false
  }

  const candidate = error as {
    code?: unknown
    message?: unknown
    meta?: { driverAdapterError?: { cause?: { kind?: unknown } } }
  }

  if (candidate.code === 'P2002') {
    return true
  }

  if (candidate.meta?.driverAdapterError?.cause?.kind === 'UniqueConstraintViolation') {
    return true
  }

  return (
    typeof candidate.message === 'string' &&
    /unique constraint|duplicate key value|\b23505\b/i.test(candidate.message)
  )
}

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

// RFC 4648 base32, lowercase, without padding (API tokens, fingerprints).
export function base32Lower(bytes: Uint8Array) {
  let output = ''
  let buffer = 0
  let bits = 0

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
    buffer &= (1 << bits) - 1
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]
  }

  return output
}
