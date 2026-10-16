import {
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
} from 'node:crypto'
import type { FastifyRequest } from 'fastify'
import { ensureAccountSystemSchema } from './account-schema.js'
import { findOwnedShareByResource, OwnedShareType } from './account-shares.js'
import {
  AuditActor,
  auditActorFor,
  recipientActor,
  recordAuditEvent,
  recordShareAccessDenied,
} from './audit.js'
import { getPrisma } from './db.js'
import { hasScope, Principal } from './principal.js'
import { base32Lower, isUniqueConstraintError } from './utils.js'
import { HttpError } from './validation.js'

// Agent identities: X25519 public keys registered by `pastevault agent init`.
// The server stores public keys only; private keys never leave the agent.

export const AGENT_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/
export const AGENT_FINGERPRINT_PATTERN = /^pvk1_[a-z2-7]{32}$/
// 32 bytes of unpadded base64url.
export const AGENT_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/

const FINGERPRINT_DOMAIN = 'pastevault:agent-key:v1'
const LAST_USED_RESOLUTION_MS = 60_000

// fingerprint = "pvk1_" + base32_lower_nopad(SHA-256(domain || 0x00 || pk)[0:20])
// (spec §3.1; the CLI and web compute the same, see testdata/crypto).
export function agentFingerprint(publicKey: Uint8Array) {
  const digest = createHash('sha256')
    .update(FINGERPRINT_DOMAIN)
    .update(Uint8Array.of(0))
    .update(publicKey)
    .digest()
  return `pvk1_${base32Lower(digest.subarray(0, 20))}`
}

// Decodes a registered public key, refusing anything that is not a usable
// X25519 key. A low-order point would make every share sealed to it readable
// by anyone (all-zero shared secret); OpenSSL refuses that exchange.
export function decodeAgentPublicKey(value: string): Buffer | null {
  if (!AGENT_PUBLIC_KEY_PATTERN.test(value)) {
    return null
  }

  const publicKey = Buffer.from(value, 'base64url')
  // Canonical text (no padding bits set) and a canonical u-coordinate, so a
  // key has exactly one encoding and one fingerprint.
  if (publicKey.length !== 32 || publicKey.toString('base64url') !== value || !isCanonicalX25519(publicKey)) {
    return null
  }

  try {
    const probe = generateKeyPairSync('x25519')
    const shared = diffieHellman({
      privateKey: probe.privateKey,
      publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: value }, format: 'jwk' }),
    })
    if (shared.every((byte) => byte === 0)) {
      return null
    }
  } catch {
    return null
  }

  return publicKey
}

// Top bit clear and u < p = 2^255 - 19 (little-endian).
export function isCanonicalX25519(publicKey: Uint8Array) {
  if (publicKey.length !== 32 || (publicKey[31]! & 0x80) !== 0) {
    return false
  }
  if (publicKey[31] !== 0x7f || publicKey[0]! < 0xed) {
    return true
  }
  return publicKey.subarray(1, 31).some((byte) => byte !== 0xff)
}

type AgentRow = NonNullable<Awaited<ReturnType<typeof findAgentForUser>>>

export function toAgentSummary(agent: AgentRow) {
  return {
    id: agent.id,
    name: agent.name,
    kind: agent.kind,
    public_key: agent.public_key,
    fingerprint: agent.fingerprint,
    created_at: agent.created_at,
    last_used_at: agent.last_used_at,
    revoked_at: agent.revoked_at,
  }
}

export async function findAgentForUser(id: string, userId: string) {
  await ensureAccountSystemSchema()
  return getPrisma().agentIdentity.findFirst({ where: { id, user_id: userId } })
}

export async function listAgents(userId: string, includeRevoked: boolean) {
  await ensureAccountSystemSchema()
  return getPrisma().agentIdentity.findMany({
    where: { user_id: userId, ...(includeRevoked ? {} : { revoked_at: null }) },
    orderBy: [{ created_at: 'asc' }, { id: 'asc' }],
  })
}

async function conflictFor(userId: string, name: string, fingerprint: string) {
  const prisma = getPrisma()
  if (await prisma.agentIdentity.findFirst({ where: { user_id: userId, name, revoked_at: null } })) {
    return new HttpError(409, {
      error: `An agent named ${name} already exists; revoke it first or choose another name`,
      code: 'agent_name_taken',
    })
  }

  // Fingerprints are unique across all accounts and stay reserved after a
  // revoke, so a key is never registered twice.
  if (await prisma.agentIdentity.findUnique({ where: { fingerprint } })) {
    return new HttpError(409, {
      error: 'This public key is already registered; generate a new key',
      code: 'public_key_taken',
    })
  }

  return null
}

// POST /api/agents. A token without an agent becomes bound to the agent it
// registers; a token can register at most one agent.
export async function registerAgent(
  principal: Principal,
  input: { name: string; public_key: string; fingerprint: string },
  request: FastifyRequest
) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  const publicKey = decodeAgentPublicKey(input.public_key)
  if (!publicKey) {
    throw new HttpError(400, {
      error: 'public_key must be a 32-byte X25519 public key (unpadded base64url) that is not a low-order point',
      code: 'invalid_public_key',
    })
  }

  // The server never trusts the client's fingerprint either.
  const fingerprint = agentFingerprint(publicKey)
  if (fingerprint !== input.fingerprint) {
    throw new HttpError(400, {
      error: 'fingerprint does not match public_key',
      code: 'fingerprint_mismatch',
    })
  }

  if (principal.kind === 'token' && principal.agent_id) {
    throw new HttpError(409, {
      error: 'This API token is already bound to an agent; a token can register only one agent',
      code: 'token_already_bound',
    })
  }

  const conflict = await conflictFor(principal.user.id, input.name, fingerprint)
  if (conflict) {
    throw conflict
  }

  let agent: AgentRow
  try {
    agent = await prisma.agentIdentity.create({
      data: {
        user_id: principal.user.id,
        kind: 'agent',
        name: input.name,
        public_key: input.public_key,
        fingerprint,
      },
    })
  } catch (error: unknown) {
    if (isUniqueConstraintError(error)) {
      throw (
        (await conflictFor(principal.user.id, input.name, fingerprint)) ??
        new HttpError(409, { error: 'The agent already exists', code: 'agent_exists' })
      )
    }
    throw error
  }

  let tokenBound = false
  if (principal.kind === 'token') {
    // Conditional, so two concurrent registrations can't both bind the token.
    const bound = await prisma.apiToken.updateMany({
      where: { id: principal.token_id, user_id: principal.user.id, agent_id: null, revoked_at: null },
      data: { agent_id: agent.id },
    })
    if (bound.count !== 1) {
      await prisma.agentIdentity.deleteMany({ where: { id: agent.id } })
      throw new HttpError(409, {
        error: 'This API token is already bound to an agent; a token can register only one agent',
        code: 'token_already_bound',
      })
    }
    tokenBound = true
  }

  await recordAuditEvent({
    user_id: principal.user.id,
    subject_type: 'agent',
    subject_id: agent.id,
    event: 'agent.registered',
    actor: auditActorFor(principal, principal.user.id),
    details: { name: agent.name, fingerprint: agent.fingerprint, token_bound: tokenBound },
    request,
  })

  return { agent, tokenBound }
}

// DELETE /api/agents/:id. Revokes the agent and every token bound to it.
// Idempotent: a second call keeps the original revocation time.
export async function revokeAgent(principal: Principal, id: string, request: FastifyRequest) {
  const existing = await findAgentForUser(id, principal.user.id)
  if (!existing) {
    return null
  }
  // A token bound to an agent acts as that agent only: it may revoke itself
  // but not the account's other agents (and their tokens).
  if (principal.agent_id && principal.agent_id !== existing.id) {
    throw new HttpError(403, {
      error: 'other_agent',
      message: 'This API token is bound to another agent and can only manage its own agent',
    })
  }
  if (existing.revoked_at) {
    return { agent: existing, tokensRevoked: 0 }
  }

  const prisma = getPrisma()
  const now = new Date()
  const agent = await prisma.agentIdentity.update({
    where: { id: existing.id },
    data: { revoked_at: now },
  })

  const tokens = await prisma.apiToken.findMany({
    where: { user_id: principal.user.id, agent_id: agent.id, revoked_at: null },
    select: { id: true, name: true, token_prefix: true },
  })
  if (tokens.length > 0) {
    await prisma.apiToken.updateMany({
      where: { id: { in: tokens.map((token) => token.id) }, revoked_at: null },
      data: { revoked_at: now },
    })
  }

  const actor = auditActorFor(principal, principal.user.id)
  // Its open secret requests are cancelled (and answers wiped): nobody may
  // answer, or collect an answer, for an agent that no longer exists.
  const { cancelRequestsOfAgent } = await import('./secret-requests.js')
  const requestsCancelled = await cancelRequestsOfAgent(principal.user.id, agent.id, actor, request)
  await recordAuditEvent({
    user_id: principal.user.id,
    subject_type: 'agent',
    subject_id: agent.id,
    event: 'agent.revoked',
    actor,
    details: {
      name: agent.name,
      fingerprint: agent.fingerprint,
      tokens_revoked: tokens.length,
      requests_cancelled: requestsCancelled,
    },
    request,
  })
  for (const token of tokens) {
    await recordAuditEvent({
      user_id: principal.user.id,
      subject_type: 'token',
      subject_id: token.id,
      event: 'token.revoked',
      actor,
      details: { name: token.name, prefix: token.token_prefix, reason: 'agent_revoked' },
      request,
    })
  }

  return { agent, tokensRevoked: tokens.length }
}

export interface ResolvedRecipient {
  fingerprint: string
  wrapped_key: string
  agent_id: string | null
  user_id: string | null
}

// Validates a share's `recipient`. With agent_id the agent must be an active
// agent of the creator's account and the fingerprint must be its stored one;
// the share then requires that account to consume it. Without agent_id the
// share is sealed to a raw public key (`--to-key`) and has no recipient auth.
export async function resolveShareRecipient(
  principal: Principal | null,
  recipient: { agent_id?: string; fingerprint: string; wrapped_key: string } | undefined
): Promise<ResolvedRecipient | null> {
  if (!recipient) {
    return null
  }

  if (recipient.agent_id === undefined) {
    return {
      fingerprint: recipient.fingerprint,
      wrapped_key: recipient.wrapped_key,
      agent_id: null,
      user_id: null,
    }
  }

  if (!principal) {
    throw new HttpError(401, {
      error: 'Authentication required',
      message: 'Sealing a share to an agent of an account requires signing in to that account',
    })
  }

  await ensureAccountSystemSchema()
  const agent = await getPrisma().agentIdentity.findFirst({
    where: { id: recipient.agent_id, user_id: principal.user.id, revoked_at: null },
    select: { id: true, fingerprint: true },
  })
  if (!agent) {
    throw new HttpError(400, {
      error: 'Unknown recipient agent',
      code: 'recipient_agent_unknown',
    })
  }
  if (agent.fingerprint !== recipient.fingerprint) {
    throw new HttpError(400, {
      error: 'recipient.fingerprint does not match the agent',
      code: 'recipient_fingerprint_mismatch',
    })
  }

  return {
    fingerprint: agent.fingerprint,
    wrapped_key: recipient.wrapped_key,
    agent_id: agent.id,
    user_id: principal.user.id,
  }
}

export function recipientDenial(
  principal: Principal | null,
  share: { recipient_user_id: string | null; recipient_agent_id: string | null }
) {
  if (!principal) {
    return 'anonymous'
  }
  if (principal.user.id !== share.recipient_user_id) {
    return 'other_account'
  }
  if (!hasScope(principal, 'shares:receive')) {
    return 'missing_scope'
  }
  // A token bound to one agent acts as that agent only: it can't take views
  // of shares sealed to the account's other agents.
  if (principal.agent_id && share.recipient_agent_id && principal.agent_id !== share.recipient_agent_id) {
    return 'other_agent'
  }
  return null
}

function touchAgent(agentId: string) {
  const now = new Date()
  void getPrisma()
    .agentIdentity.updateMany({
      where: {
        id: agentId,
        OR: [
          { last_used_at: null },
          { last_used_at: { lt: new Date(now.getTime() - LAST_USED_RESOLUTION_MS) } },
        ],
      },
      data: { last_used_at: now },
    })
    .catch(() => undefined)
}

// Recipient auth for consuming GETs. Must run before a view is consumed. For
// a share sealed to an account agent, only that account (with
// shares:receive) may take a view; anyone else gets 403 and the owner's log
// records share.access_denied. Returns the audit actor for the views of a
// recipient, or null when the share has no recipient auth.
export async function requireRecipientAccess(
  request: FastifyRequest,
  principal: Principal | null,
  shareType: OwnedShareType,
  share: { id: string; recipient_user_id: string | null; recipient_agent_id: string | null }
): Promise<AuditActor | null> {
  if (!share.recipient_user_id) {
    return null
  }

  const denial = recipientDenial(principal, share)
  if (denial) {
    const owned = await findOwnedShareByResource(shareType, share.id).catch(() => null)
    if (owned) {
      await recordShareAccessDenied(owned, auditActorFor(principal, owned.user_id), denial, request)
    }
    throw new HttpError(403, {
      error: 'recipient_auth_required',
      message:
        denial === 'missing_scope'
          ? 'This share is sealed to an agent; the credential needs the shares:receive scope'
          : denial === 'other_agent'
            ? 'This share is sealed to another agent than the one this API token is bound to'
            : "This share is sealed to an agent; open it with the recipient account's credentials (pastevault get)",
    })
  }

  if (share.recipient_agent_id) {
    touchAgent(share.recipient_agent_id)
  }
  return recipientActor(principal!, share.recipient_agent_id)
}
