import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { nanoid } from 'nanoid'

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
