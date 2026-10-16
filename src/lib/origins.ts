import type { FastifyRequest } from 'fastify'
import { config } from './config.js'

// Browser origins the server trusts: for CORS, for better-auth's own origin
// checks, and for the CSRF check on cookie-authenticated writes. A request's
// own origin is always trusted on top of this list.

export function splitOrigins(value?: string) {
  if (!value) {
    return []
  }

  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
}

export function resolveAuthBaseURL() {
  const explicitBaseUrl = process.env.BETTER_AUTH_URL || config.BETTER_AUTH_URL

  if (explicitBaseUrl) {
    return explicitBaseUrl
  }

  const port = process.env.PORT || String(config.PORT)
  return `http://localhost:${port}/api/auth`
}

// BETTER_AUTH_TRUSTED_ORIGINS, CORS_ORIGIN, the auth base URL and, outside
// production, the local dev servers. Read from process.env at call time
// because `pastevault up` fills in defaults before routes load.
export function resolveTrustedOrigins() {
  const origins = new Set<string>()

  for (const origin of splitOrigins(
    process.env.BETTER_AUTH_TRUSTED_ORIGINS || config.BETTER_AUTH_TRUSTED_ORIGINS
  )) {
    origins.add(origin)
  }

  const corsOrigin = process.env.CORS_ORIGIN || config.CORS_ORIGIN
  if (corsOrigin && corsOrigin !== '*') {
    for (const origin of splitOrigins(corsOrigin)) {
      origins.add(origin)
    }
  }

  origins.add(new URL(resolveAuthBaseURL()).origin)

  if (config.NODE_ENV !== 'production') {
    const currentPort = process.env.PORT || String(config.PORT)
    origins.add(`http://localhost:${currentPort}`)
    origins.add('http://localhost:3001')
    origins.add('http://localhost:3002')
    origins.add(`http://127.0.0.1:${currentPort}`)
    origins.add('http://127.0.0.1:3001')
    origins.add('http://127.0.0.1:3002')
  }

  return [...origins]
}

function normalizeOrigin(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : null
  } catch {
    return null
  }
}

interface OriginMatcher {
  exact: Set<string>
  patterns: RegExp[]
}

let matcher: OriginMatcher | undefined

// Built once, on first use (after the CLI has set its environment). A bare
// "*" is never honoured; "https://*.example.com" style patterns are.
function trustedOriginMatcher(): OriginMatcher {
  if (matcher) {
    return matcher
  }

  const exact = new Set<string>()
  const patterns: RegExp[] = []

  for (const entry of resolveTrustedOrigins()) {
    if (entry === '*') {
      continue
    }

    if (entry.includes('*')) {
      const source = entry
        .replace(/\/+$/, '')
        .split('*')
        .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('[a-z0-9-]+(?:\\.[a-z0-9-]+)*')
      patterns.push(new RegExp(`^${source}$`, 'i'))
      continue
    }

    const normalized = normalizeOrigin(entry)
    if (normalized) {
      exact.add(normalized)
    }
  }

  matcher = { exact, patterns }
  return matcher
}

// The origin of the request itself, as the browser addressed it. Honours
// X-Forwarded-Proto/Host only when TRUST_PROXY is configured.
function requestOrigin(request: FastifyRequest) {
  return normalizeOrigin(`${request.protocol}://${request.host}`)
}

export function isTrustedOrigin(origin: string | undefined, request: FastifyRequest) {
  if (!origin) {
    return false
  }

  const normalized = normalizeOrigin(origin)
  if (!normalized) {
    // "null" (sandboxed frames, file://) and anything unparsable.
    return false
  }

  if (normalized === requestOrigin(request)) {
    return true
  }

  const { exact, patterns } = trustedOriginMatcher()
  return exact.has(normalized) || patterns.some((pattern) => pattern.test(normalized))
}

const CORS_ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Requested-With',
  'Accept',
  'Origin',
  'Referer',
  'X-Upload-Token',
  'X-Download-Grant',
]

// @fastify/cors options delegator: only trusted origins get CORS headers, so
// other sites can neither read API responses with the user's cookies nor pass
// a preflight. Requests without an Origin (CLI, curl) are unaffected.
export function corsOptionsDelegator(
  request: FastifyRequest,
  callback: (error: Error | null, options: Record<string, unknown>) => void
) {
  callback(null, {
    origin: isTrustedOrigin(request.headers.origin, request),
    credentials: true,
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: CORS_ALLOWED_HEADERS,
    exposedHeaders: ['*'],
    preflightContinue: false,
    optionsSuccessStatus: 200,
  })
}
