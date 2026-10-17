import { randomBytes } from 'node:crypto'
import { ensureAccountSystemSchema } from './account-schema.js'
import { getPrisma } from './db.js'
import { base32Lower, hashSecretToken } from './utils.js'

export const SCOPES = [
  'shares:create',
  'shares:read',
  'shares:revoke',
  'shares:receive',
  'agents:read',
  'agents:write',
  'requests:create',
  'audit:read',
] as const
export type Scope = (typeof SCOPES)[number]

// Tokens can't register or revoke agents unless that is asked for explicitly.
export const DEFAULT_TOKEN_SCOPES: Scope[] = SCOPES.filter((scope) => scope !== 'agents:write')

export const API_TOKEN_PREFIX = 'pv_pat_'
// "pv_pat_" plus 52 lowercase base32 characters (260 random bits). The fixed
// prefix makes leaked tokens easy for secret scanners to find.
const API_TOKEN_PATTERN = /^pv_pat_[a-z2-7]{52}$/
const API_TOKEN_BODY_LENGTH = 52
// Shown in listings so people can tell tokens apart: "pv_pat_" + 5 characters.
const API_TOKEN_DISPLAY_PREFIX_LENGTH = 12
const LAST_USED_RESOLUTION_MS = 60_000

export function isApiTokenString(value: string) {
  return value.startsWith(API_TOKEN_PREFIX)
}

export function generateApiToken() {
  return API_TOKEN_PREFIX + base32Lower(randomBytes(33)).slice(0, API_TOKEN_BODY_LENGTH)
}

export function parseScopes(value: string): Scope[] {
  const known = new Set<string>(SCOPES)
  return value.split(/\s+/).filter((scope): scope is Scope => known.has(scope))
}

export function serializeScopes(scopes: readonly Scope[]) {
  // Stored in canonical order so listings are stable.
  return SCOPES.filter((scope) => scopes.includes(scope)).join(' ')
}

// Resolves a presented token to its active record. The lookup is by SHA-256
// hash only (never by prefix), so response timing says nothing about how much
// of a guessed token was right.
export async function findActiveApiToken(token: string) {
  if (!API_TOKEN_PATTERN.test(token)) {
    return null
  }

  await ensureAccountSystemSchema()
  const prisma = getPrisma()
  const record = await prisma.apiToken.findUnique({
    where: { token_hash: hashSecretToken(token) },
    include: {
      user: {
        select: { id: true, name: true, username: true },
      },
    },
  })

  const now = new Date()
  if (
    !record ||
    record.revoked_at ||
    (record.expires_at && record.expires_at.getTime() <= now.getTime())
  ) {
    return null
  }

  // A token bound to an agent dies with it. Revoking an agent also revokes its
  // tokens; this check covers anything that slipped past that.
  if (record.agent_id) {
    const agent = await prisma.agentIdentity.findUnique({
      where: { id: record.agent_id },
      select: { revoked_at: true, user_id: true },
    })
    if (!agent || agent.revoked_at || agent.user_id !== record.user_id) {
      return null
    }
  }

  // Coarse last-used tracking: at most one write per token per minute.
  if (
    !record.last_used_at ||
    now.getTime() - record.last_used_at.getTime() >= LAST_USED_RESOLUTION_MS
  ) {
    void prisma.apiToken
      .updateMany({
        where: {
          id: record.id,
          OR: [
            { last_used_at: null },
            { last_used_at: { lt: new Date(now.getTime() - LAST_USED_RESOLUTION_MS) } },
          ],
        },
        data: { last_used_at: now },
      })
      .catch(() => undefined)

    // An agent-bound token acts as its agent, so it counts as agent use.
    if (record.agent_id) {
      void prisma.agentIdentity
        .updateMany({ where: { id: record.agent_id }, data: { last_used_at: now } })
        .catch(() => undefined)
    }
  }

  return record
}

export async function createApiToken(input: {
  user_id: string
  name: string
  scopes: readonly Scope[]
  expires_at: Date | null
  agent_id: string | null
}) {
  await ensureAccountSystemSchema()
  const token = generateApiToken()
  const record = await getPrisma().apiToken.create({
    data: {
      user_id: input.user_id,
      name: input.name,
      token_prefix: token.slice(0, API_TOKEN_DISPLAY_PREFIX_LENGTH),
      token_hash: hashSecretToken(token),
      scopes: serializeScopes(input.scopes),
      expires_at: input.expires_at,
      agent_id: input.agent_id,
    },
  })

  return { record, token }
}

// Only for backing out a token that was never handed out.
export async function deleteApiToken(id: string) {
  await getPrisma().apiToken.deleteMany({ where: { id } })
}

export async function countActiveApiTokens(userId: string) {
  await ensureAccountSystemSchema()
  return getPrisma().apiToken.count({
    where: {
      user_id: userId,
      revoked_at: null,
      OR: [{ expires_at: null }, { expires_at: { gt: new Date() } }],
    },
  })
}

export async function listApiTokens(userId: string) {
  await ensureAccountSystemSchema()
  return getPrisma().apiToken.findMany({
    where: { user_id: userId },
    orderBy: [{ created_at: 'desc' }, { id: 'desc' }],
  })
}

export async function getApiTokenForUser(id: string, userId: string) {
  await ensureAccountSystemSchema()
  return getPrisma().apiToken.findFirst({
    where: { id, user_id: userId },
  })
}

export async function revokeApiToken(id: string) {
  await ensureAccountSystemSchema()
  return getPrisma().apiToken.update({
    where: { id },
    data: { revoked_at: new Date() },
  })
}
