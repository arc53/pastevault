import type { FastifyRequest } from 'fastify'
import {
  findActiveApiToken,
  isApiTokenString,
  parseScopes,
  SCOPES,
  Scope,
} from './api-tokens.js'
import { config } from './config.js'
import { isTrustedOrigin } from './origins.js'
import { HttpError } from './validation.js'

export { SCOPES, DEFAULT_TOKEN_SCOPES } from './api-tokens.js'
export type { Scope } from './api-tokens.js'

export interface PrincipalUser {
  id: string
  name: string
  username: string | null
}

// Who is making a request: a browser/CLI session (better-auth) or a personal
// access token. Sessions implicitly hold every scope.
export type Principal =
  | {
      kind: 'session'
      user: PrincipalUser
      scopes: readonly Scope[]
      token_id: null
      agent_id: null
    }
  | {
      kind: 'token'
      user: PrincipalUser
      scopes: readonly Scope[]
      token_id: string
      agent_id: string | null
    }

export type SessionPrincipal = Extract<Principal, { kind: 'session' }>

const AUTHENTICATION_REQUIRED = { error: 'Authentication required' }
const INVALID_TOKEN = { error: 'invalid_token' }

const resolved = new WeakMap<FastifyRequest, Promise<Principal | null>>()

export function readBearerToken(request: FastifyRequest) {
  const header = request.headers.authorization
  const match = typeof header === 'string' ? /^Bearer\s+(\S+)\s*$/i.exec(header) : null
  return match?.[1]
}

export function presentsApiToken(request: FastifyRequest) {
  const bearer = readBearerToken(request)
  return Boolean(bearer && isApiTokenString(bearer))
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// CSRF defence for cookie sessions. A browser attaches the session cookie to
// cross-site requests too, and SameSite=Lax doesn't cover same-site origins
// (sibling subdomains, other localhost ports), so a state-changing request
// carrying a cookie must come from a trusted origin. Browsers always send
// Origin on such requests; clients without one (CLI, curl) are not browsers.
// Bearer credentials can't be attached by another site, so they're exempt.
function assertCookieWriteOrigin(request: FastifyRequest) {
  if (SAFE_METHODS.has(request.method) || readBearerToken(request)) {
    return
  }

  const origin = request.headers.origin
  if (origin !== undefined && !isTrustedOrigin(origin, request)) {
    throw new HttpError(403, { error: 'origin_not_allowed' })
  }
}

async function resolveSession(request: FastifyRequest): Promise<Principal | null> {
  let session: Awaited<ReturnType<typeof getBetterAuthSession>>
  try {
    session = await getBetterAuthSession(request)
  } catch {
    return null
  }

  if (!session) {
    return null
  }

  assertCookieWriteOrigin(request)

  const user = session.user as { id: string; name: string; username?: string | null }
  return {
    kind: 'session',
    user: { id: user.id, name: user.name, username: user.username ?? null },
    scopes: SCOPES,
    token_id: null,
    agent_id: null,
  }
}

async function getBetterAuthSession(request: FastifyRequest) {
  const [{ fromNodeHeaders }, { auth }] = await Promise.all([
    import('better-auth/node'),
    import('./auth.js'),
  ])
  return auth.api.getSession({
    headers: fromNodeHeaders(request.raw.headers),
  })
}

async function resolve(request: FastifyRequest): Promise<Principal | null> {
  if (config.DISABLE_AUTH) {
    return null
  }

  const bearer = readBearerToken(request)
  if (!bearer || !isApiTokenString(bearer)) {
    return resolveSession(request)
  }

  // An API token is never handed to better-auth, and a bad one is an error
  // rather than a silent fall back to anonymous access.
  const token = await findActiveApiToken(bearer)
  if (!token) {
    throw new HttpError(401, INVALID_TOKEN)
  }

  return {
    kind: 'token',
    user: token.user,
    scopes: parseScopes(token.scopes),
    token_id: token.id,
    agent_id: token.agent_id,
  }
}

// The authenticated principal, or null for anonymous requests. Throws 401
// invalid_token for an unknown, revoked or expired API token. Memoised per
// request.
export function getPrincipal(request: FastifyRequest): Promise<Principal | null> {
  let principal = resolved.get(request)
  if (!principal) {
    principal = resolve(request)
    resolved.set(request, principal)
  }
  return principal
}

export function hasScope(principal: Principal, scope: Scope) {
  return principal.scopes.includes(scope)
}

export function requireScope(principal: Principal, scope: Scope) {
  if (!hasScope(principal, scope)) {
    throw new HttpError(403, { error: 'insufficient_scope', required: scope })
  }
}

// Any authenticated principal, optionally holding `scope`.
export async function requirePrincipal(request: FastifyRequest, scope?: Scope) {
  const principal = await getPrincipal(request)
  if (!principal) {
    throw new HttpError(401, AUTHENTICATION_REQUIRED)
  }

  if (scope) {
    requireScope(principal, scope)
  }

  return principal
}

// Account management that tokens must never do (minting or revoking tokens).
export async function requireSession(request: FastifyRequest): Promise<SessionPrincipal> {
  const principal = await requirePrincipal(request)
  if (principal.kind !== 'session') {
    throw new HttpError(403, { error: 'session_required' })
  }

  return principal
}
