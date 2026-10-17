import { randomBytes } from 'node:crypto'
import type { FastifyRequest } from 'fastify'
import { ensureAccountSystemSchema } from './account-schema.js'
import { decodeAgentPublicKey, agentFingerprint } from './agents.js'
import { AuditActor, AuditEventName, auditActorFor, recordAuditEvent, SYSTEM_ACTOR } from './audit.js'
import { config } from './config.js'
import { getPrisma } from './db.js'
import type { Principal, SessionPrincipal } from './principal.js'
import { generateSecretToken, hashSecretToken, isUniqueConstraintError, secretTokenMatches } from './utils.js'
import { HttpError, SECRET_REQUEST_CODE_ALPHABET } from './validation.js'
import type {
  PollSecretRequestResponse,
  SecretRequestAccept,
  SecretRequestByCodeResponse,
  SecretRequestResponseKind,
  SecretRequestStatus,
  SecretRequestSummary,
} from '../types/index.js'

// Secret requests (spec §2.6, §6). An agent (API token with requests:create
// and a registered agent identity) asks its own account's human for a
// secret. The human answers in the browser, signed in to the same account,
// and seals the answer to the request's ephemeral X25519 key; the server
// stores ciphertext only, hands it to the poller once (re-pollable for
// DELIVERY_LEASE_MS) and wipes it on ack, after the lease, or on expiry.

export const POLL_INTERVAL_SECONDS = 3
export const DELIVERY_LEASE_MS = 120_000
// Clients that sleep exactly `interval` can arrive a little early.
const POLL_SLACK_MS = 500
const MAX_PENDING_PER_USER = 20
const MAX_CREATED_PER_HOUR = 30
const LIST_LIMIT = 200

const CODE_LENGTH = 8
const CODE_PATTERN = new RegExp(`^[${SECRET_REQUEST_CODE_ALPHABET}]{${CODE_LENGTH}}$`)

const WIPED_RESPONSE = {
  response_ciphertext: null,
  response_nonce: null,
  response_wrapped_key: null,
}

// The alphabet has 32 characters, so `byte & 31` is uniform.
export function generateRequestCode() {
  return Array.from(randomBytes(CODE_LENGTH), (byte) => SECRET_REQUEST_CODE_ALPHABET[byte & 31]).join('')
}

export function formatRequestCode(code: string) {
  return `${code.slice(0, 4)}-${code.slice(4)}`
}

// "abcd-efgh", "ABCD EFGH" and "ABCDEFGH" all name the same request.
export function normalizeRequestCode(input: string) {
  const code = input.replace(/[\s-]/g, '').toUpperCase()
  return CODE_PATTERN.test(code) ? code : null
}

async function prisma() {
  await ensureAccountSystemSchema()
  return getPrisma()
}

type SecretRequestRow = NonNullable<Awaited<ReturnType<ReturnType<typeof getPrisma>['secretRequest']['findUnique']>>>

function notFound(): HttpError {
  return new HttpError(404, { error: 'Secret request not found' })
}

function recordRequestEvent(
  row: SecretRequestRow,
  event: AuditEventName,
  actor: AuditActor,
  details: Record<string, unknown> = {},
  request?: FastifyRequest
) {
  return recordAuditEvent({
    user_id: row.user_id,
    subject_type: 'secret_request',
    subject_id: row.id,
    event,
    actor,
    details: { name: row.name, code: formatRequestCode(row.code), ...details },
    request,
  })
}

// The requester's side (create, poll, ack, cancel by token) is attributed to
// the requesting agent even when the token itself is not bound to it.
function requesterActor(principal: Principal, row: { requester_agent_id: string }): AuditActor {
  if (principal.kind === 'token') {
    return { kind: 'owner', token_id: principal.token_id, agent_id: principal.agent_id ?? row.requester_agent_id }
  }
  return auditActorFor(principal, principal.user.id)
}

// A token bound to an agent acts as that agent only (as for sealed shares):
// it can't poll, ack or cancel another agent's requests.
function assertAgentBinding(principal: Principal, row: { requester_agent_id: string }) {
  if (principal.agent_id && principal.agent_id !== row.requester_agent_id) {
    throw new HttpError(403, {
      error: 'other_agent',
      message: 'This API token is bound to another agent than the one that made this request',
    })
  }
}

async function reload(id: string) {
  const row = await (await prisma()).secretRequest.findUnique({ where: { id } })
  if (!row) {
    throw notFound()
  }
  return row
}

// Lazy expiry and wiping, run by every handler (and by the cron): a pending
// or fulfilled request past expires_at becomes expired (its response, if
// any, is wiped), and a delivered response is wiped once its re-poll lease
// is over.
export async function settleSecretRequest(row: SecretRequestRow, request?: FastifyRequest) {
  const db = await prisma()
  const now = new Date()

  // A revoked agent's requests die with it.
  if (isLive(row)) {
    const agent = await db.agentIdentity.findUnique({
      where: { id: row.requester_agent_id },
      select: { revoked_at: true },
    })
    if (!agent || agent.revoked_at) {
      await cancelForRevokedAgent(row, SYSTEM_ACTOR, request)
      return reload(row.id)
    }
  }

  if ((row.status === 'pending' || row.status === 'fulfilled') && row.expires_at.getTime() <= now.getTime()) {
    const result = await db.secretRequest.updateMany({
      where: { id: row.id, status: { in: ['pending', 'fulfilled'] }, expires_at: { lte: now } },
      data: { status: 'expired', closed_at: now, ...WIPED_RESPONSE },
    })
    if (result.count === 1) {
      await recordRequestEvent(row, 'request.expired', SYSTEM_ACTOR, { was: row.status }, request)
    }
    return reload(row.id)
  }

  if (
    row.status === 'delivered' &&
    row.response_ciphertext !== null &&
    (!row.delivered_at || now.getTime() - row.delivered_at.getTime() >= DELIVERY_LEASE_MS)
  ) {
    await db.secretRequest.updateMany({
      where: { id: row.id, status: 'delivered' },
      data: WIPED_RESPONSE,
    })
    return reload(row.id)
  }

  return row
}

// Pending or answered requests, and delivered answers still on the server.
function isLive(row: SecretRequestRow) {
  return (
    row.status === 'pending' ||
    row.status === 'fulfilled' ||
    (row.status === 'delivered' && row.response_ciphertext !== null)
  )
}

async function cancelForRevokedAgent(row: SecretRequestRow, actor: AuditActor, request?: FastifyRequest) {
  const db = await prisma()
  if (row.status === 'delivered') {
    await db.secretRequest.updateMany({ where: { id: row.id, status: 'delivered' }, data: WIPED_RESPONSE })
    return
  }

  const result = await db.secretRequest.updateMany({
    where: { id: row.id, status: { in: ['pending', 'fulfilled'] } },
    data: { status: 'cancelled', closed_at: new Date(), ...WIPED_RESPONSE },
  })
  if (result.count === 1) {
    await recordRequestEvent(row, 'request.cancelled', actor, { was: row.status, reason: 'agent_revoked' }, request)
  }
}

// Called when an agent is revoked: its open requests are cancelled and any
// answer still on the server is wiped.
export async function cancelRequestsOfAgent(
  userId: string,
  agentId: string,
  actor: AuditActor,
  request?: FastifyRequest
) {
  const db = await prisma()
  const rows = await db.secretRequest.findMany({
    where: {
      user_id: userId,
      requester_agent_id: agentId,
      OR: [{ status: { in: ['pending', 'fulfilled'] } }, { status: 'delivered', response_ciphertext: { not: null } }],
    },
    take: 1000,
  })
  for (const row of rows) {
    await cancelForRevokedAgent(row, actor, request)
  }
  return rows.length
}

// Wipes a delivered response when its lease ends, so a response that is
// never acked doesn't wait for the next cleanup run. The cron covers restarts.
function scheduleLeaseWipe(id: string) {
  const timer = setTimeout(() => {
    void (async () => {
      const row = await (await prisma()).secretRequest.findUnique({ where: { id } })
      if (row) {
        await settleSecretRequest(row)
      }
    })().catch(() => undefined)
  }, DELIVERY_LEASE_MS + 1000)
  timer.unref()
}

// ── create ───────────────────────────────────────────────────────────────

async function checkCreationLimits(userId: string) {
  const db = await prisma()
  const now = new Date()
  const pending = await db.secretRequest.count({
    where: { user_id: userId, status: 'pending', expires_at: { gt: now } },
  })
  if (pending > MAX_PENDING_PER_USER) {
    return {
      error: 'too_many_pending_requests',
      message: `An account can have at most ${MAX_PENDING_PER_USER} pending secret requests; cancel some or wait for them to expire`,
    }
  }

  const lastHour = await db.secretRequest.count({
    where: { user_id: userId, created_at: { gte: new Date(now.getTime() - 60 * 60 * 1000) } },
  })
  if (lastHour > MAX_CREATED_PER_HOUR) {
    return {
      error: 'rate_limited',
      message: `An account can create at most ${MAX_CREATED_PER_HOUR} secret requests per hour`,
    }
  }

  return null
}

export async function createSecretRequest(
  principal: Principal,
  input: {
    name: string
    reason?: string
    ttl_seconds: number
    accept: SecretRequestAccept
    public_key: string
    fingerprint: string
    agent_id: string
  },
  request: FastifyRequest
) {
  const db = await prisma()

  // A request speaks for an agent ("builder asks for OPENAI_API_KEY"), so
  // only that agent may make it: a token bound to it, or the account's own
  // login session. An unbound token (e.g. a leaked CI token) could otherwise
  // impersonate any agent of the account.
  if (principal.kind === 'token' && principal.agent_id !== input.agent_id) {
    throw new HttpError(403, {
      error: principal.agent_id ? 'other_agent' : 'agent_bound_token_required',
      message: principal.agent_id
        ? 'This API token is bound to another agent; a request must name the agent the token is bound to'
        : 'Secret requests need an API token bound to the requesting agent (pastevault token create --agent NAME) or a login session',
    })
  }

  const agent = await db.agentIdentity.findFirst({
    where: { id: input.agent_id, user_id: principal.user.id, revoked_at: null },
    select: { id: true, name: true },
  })
  if (!agent) {
    throw new HttpError(400, {
      error: 'Unknown requester agent: agent_id must be an active agent of this account (pastevault agent init)',
      code: 'requester_agent_unknown',
    })
  }

  const publicKey = decodeAgentPublicKey(input.public_key)
  if (!publicKey) {
    throw new HttpError(400, {
      error: 'public_key must be a 32-byte X25519 public key (unpadded base64url) that is not a low-order point',
      code: 'invalid_public_key',
    })
  }
  if (agentFingerprint(publicKey) !== input.fingerprint) {
    throw new HttpError(400, { error: 'fingerprint does not match public_key', code: 'fingerprint_mismatch' })
  }

  // Counted before (cheap refusal) and after creating (concurrent creates):
  // the new row counts itself, hence `>` in checkCreationLimits.
  const before = await checkCreationLimits(principal.user.id)
  if (before) {
    throw new HttpError(429, before)
  }

  const pollToken = generateSecretToken()
  const now = new Date()
  let row: SecretRequestRow | null = null
  for (let attempt = 0; attempt < 5 && !row; attempt++) {
    try {
      row = await db.secretRequest.create({
        data: {
          code: generateRequestCode(),
          user_id: principal.user.id,
          requester_agent_id: agent.id,
          requester_token_id: principal.token_id,
          name: input.name,
          reason: input.reason ?? null,
          accept: input.accept,
          public_key: input.public_key,
          fingerprint: input.fingerprint,
          poll_token_hash: hashSecretToken(pollToken),
          poll_interval: POLL_INTERVAL_SECONDS,
          status: 'pending',
          created_at: now,
          expires_at: new Date(now.getTime() + input.ttl_seconds * 1000),
        },
      })
    } catch (error: unknown) {
      if (!isUniqueConstraintError(error)) {
        throw error
      }
    }
  }
  if (!row) {
    throw new Error('Could not allocate a unique secret request code')
  }

  const after = await checkCreationLimits(principal.user.id)
  if (after) {
    await db.secretRequest.deleteMany({ where: { id: row.id } })
    throw new HttpError(429, after)
  }

  await recordRequestEvent(
    row,
    'request.created',
    requesterActor(principal, row),
    { accept: row.accept, ttl_seconds: input.ttl_seconds, agent: agent.name },
    request
  )

  return { row, pollToken }
}

// ── the human's side: by-code, fulfill, decline ─────────────────────────

// Per user and minute: at most BY_CODE_MISSES_PER_MINUTE lookups that find
// nothing (the guard against guessing codes of the same account; other
// accounts' codes are misses too), and BY_CODE_TOTAL_PER_MINUTE in all, so
// the request page can poll its own request every few seconds.
const BY_CODE_MISSES_PER_MINUTE = 20
const BY_CODE_TOTAL_PER_MINUTE = 120
const byCodeLookups = new Map<string, { misses: number[]; total: number[] }>()

function recentLookups(userId: string, now: number) {
  const entry = byCodeLookups.get(userId) ?? { misses: [], total: [] }
  entry.misses = entry.misses.filter((time) => now - time < 60_000)
  entry.total = entry.total.filter((time) => now - time < 60_000)
  byCodeLookups.set(userId, entry)
  return entry
}

function checkByCodeRate(userId: string) {
  const now = Date.now()
  const entry = recentLookups(userId, now)
  if (entry.misses.length >= BY_CODE_MISSES_PER_MINUTE || entry.total.length >= BY_CODE_TOTAL_PER_MINUTE) {
    throw new HttpError(429, { error: 'rate_limited', message: 'Too many secret request lookups; wait a minute' })
  }
  entry.total.push(now)

  if (byCodeLookups.size > 10_000) {
    for (const [key, value] of byCodeLookups) {
      if (value.total.every((time) => now - time >= 60_000)) {
        byCodeLookups.delete(key)
      }
    }
  }
}

function recordByCodeMiss(userId: string) {
  recentLookups(userId, Date.now()).misses.push(Date.now())
}

async function findOwnRequest(userId: string, id: string) {
  const row = await (await prisma()).secretRequest.findFirst({ where: { id, user_id: userId } })
  if (!row) {
    throw notFound()
  }
  return row
}

export async function getSecretRequestByCode(
  principal: SessionPrincipal,
  rawCode: string,
  request: FastifyRequest
): Promise<SecretRequestByCodeResponse> {
  checkByCodeRate(principal.user.id)
  const code = normalizeRequestCode(rawCode)
  const db = await prisma()
  const found = code ? await db.secretRequest.findUnique({ where: { code } }) : null
  // Another account's code is indistinguishable from a missing one.
  if (!found || found.user_id !== principal.user.id) {
    recordByCodeMiss(principal.user.id)
    throw notFound()
  }

  let row = await settleSecretRequest(found, request)
  if (!row.opened_at) {
    const now = new Date()
    const opened = await db.secretRequest.updateMany({
      where: { id: row.id, opened_at: null },
      data: { opened_at: now },
    })
    if (opened.count === 1) {
      await recordRequestEvent(row, 'request.opened', auditActorFor(principal, row.user_id), {}, request)
    }
    row = await reload(row.id)
  }

  const [agent, token] = await Promise.all([
    db.agentIdentity.findUnique({
      where: { id: row.requester_agent_id },
      select: { id: true, name: true, fingerprint: true },
    }),
    row.requester_token_id
      ? db.apiToken.findUnique({ where: { id: row.requester_token_id }, select: { name: true } })
      : null,
  ])

  return {
    id: row.id,
    code: formatRequestCode(row.code),
    name: row.name,
    reason: row.reason,
    accept: row.accept as SecretRequestAccept,
    public_key: row.public_key,
    fingerprint: row.fingerprint,
    max_bytes: config.MAX_SECRET_REQUEST_BYTES,
    requester: {
      agent: {
        id: row.requester_agent_id,
        name: agent?.name ?? null,
        fingerprint: agent?.fingerprint ?? null,
      },
      token_name: token?.name ?? null,
    },
    status: row.status as SecretRequestStatus,
    created_at: row.created_at,
    expires_at: row.expires_at,
    opened_at: row.opened_at,
    fulfilled_at: row.fulfilled_at,
    delivered_at: row.delivered_at,
    closed_at: row.closed_at,
  }
}

function assertPending(row: SecretRequestRow) {
  if (row.status === 'expired') {
    throw new HttpError(410, { error: 'expired', message: 'This secret request has expired' })
  }
  if (row.status !== 'pending') {
    throw new HttpError(409, {
      error: 'not_pending',
      status: row.status,
      message: `This secret request is already ${row.status}`,
    })
  }
}

export async function fulfillSecretRequest(
  principal: SessionPrincipal,
  id: string,
  input: { kind: SecretRequestResponseKind; ciphertext: string; nonce: string; wrapped_key: string },
  request: FastifyRequest
) {
  const row = await settleSecretRequest(await findOwnRequest(principal.user.id, id), request)
  assertPending(row)

  if (row.accept !== 'any' && row.accept !== input.kind) {
    throw new HttpError(400, {
      error: `This request accepts ${row.accept} only`,
      code: 'kind_not_accepted',
    })
  }

  const ciphertext = Buffer.from(input.ciphertext, 'base64url')
  if (ciphertext.toString('base64url') !== input.ciphertext || ciphertext.length < 17) {
    throw new HttpError(400, { error: 'ciphertext must be unpadded base64url of an XChaCha20-Poly1305 ciphertext' })
  }
  if (ciphertext.length > config.MAX_SECRET_REQUEST_BYTES) {
    throw new HttpError(413, {
      error: 'too_large',
      message: `The sealed response may be at most ${config.MAX_SECRET_REQUEST_BYTES} bytes`,
      max_bytes: config.MAX_SECRET_REQUEST_BYTES,
    })
  }

  const now = new Date()
  const db = await prisma()
  const result = await db.secretRequest.updateMany({
    where: { id: row.id, status: 'pending', expires_at: { gt: now } },
    data: {
      status: 'fulfilled',
      response_kind: input.kind,
      response_ciphertext: input.ciphertext,
      response_nonce: input.nonce,
      response_wrapped_key: input.wrapped_key,
      response_size: ciphertext.length,
      fulfilled_by_user_id: principal.user.id,
      fulfilled_at: now,
    },
  })
  if (result.count !== 1) {
    // Lost a race with an expiry, decline, cancel or another fulfilment.
    assertPending(await settleSecretRequest(await reload(row.id), request))
    throw new HttpError(409, { error: 'not_pending', message: 'This secret request changed meanwhile' })
  }

  await recordRequestEvent(
    row,
    'request.fulfilled',
    auditActorFor(principal, row.user_id),
    { kind: input.kind, size: ciphertext.length },
    request
  )
  return { status: 'fulfilled' as const }
}

export async function declineSecretRequest(principal: SessionPrincipal, id: string, request: FastifyRequest) {
  const row = await settleSecretRequest(await findOwnRequest(principal.user.id, id), request)
  assertPending(row)

  const now = new Date()
  const result = await (await prisma()).secretRequest.updateMany({
    where: { id: row.id, status: 'pending' },
    data: { status: 'declined', closed_at: now },
  })
  if (result.count !== 1) {
    assertPending(await reload(row.id))
  }

  await recordRequestEvent(row, 'request.declined', auditActorFor(principal, row.user_id), {}, request)
  return { status: 'declined' as const }
}

// ── the agent's side: poll, ack, cancel ─────────────────────────────────

async function findPolledRequest(principal: Principal, id: string, pollToken: string) {
  const row = await findOwnRequest(principal.user.id, id)
  assertAgentBinding(principal, row)
  if (!secretTokenMatches(pollToken, row.poll_token_hash)) {
    throw new HttpError(403, { error: 'invalid_poll_token', message: 'The poll token does not belong to this request' })
  }
  return row
}

function payload(row: SecretRequestRow) {
  return {
    kind: row.response_kind as SecretRequestResponseKind,
    ciphertext: row.response_ciphertext!,
    nonce: row.response_nonce!,
    wrapped_key: row.response_wrapped_key!,
  }
}

export async function pollSecretRequest(
  principal: Principal,
  id: string,
  pollToken: string,
  request: FastifyRequest
): Promise<PollSecretRequestResponse> {
  let row = await settleSecretRequest(await findPolledRequest(principal, id, pollToken), request)
  const db = await prisma()
  const interval = row.poll_interval
  const now = new Date()

  // One poll per interval, enforced atomically so parallel polls can't
  // both pass.
  const allowed = await db.secretRequest.updateMany({
    where: {
      id: row.id,
      OR: [
        { last_polled_at: null },
        { last_polled_at: { lte: new Date(now.getTime() - interval * 1000 + POLL_SLACK_MS) } },
      ],
    },
    data: { last_polled_at: now },
  })
  if (allowed.count !== 1) {
    throw new HttpError(429, {
      error: 'slow_down',
      message: `Poll at most once every ${interval} seconds`,
      interval,
    })
  }

  if (row.status === 'fulfilled') {
    const delivered = await db.secretRequest.updateMany({
      where: { id: row.id, status: 'fulfilled', expires_at: { gt: now } },
      data: { status: 'delivered', delivered_at: now },
    })
    if (delivered.count === 1) {
      await recordRequestEvent(row, 'request.delivered', requesterActor(principal, row), {}, request)
      scheduleLeaseWipe(row.id)
      return { status: 'fulfilled', interval, ...payload(row) }
    }
    row = await settleSecretRequest(await reload(row.id), request)
  }

  // Re-poll within the lease (e.g. the agent crashed before its ack) gets
  // the same payload again.
  if (row.status === 'delivered' && row.response_ciphertext !== null) {
    return { status: 'fulfilled', interval, ...payload(row) }
  }

  return { status: row.status as Exclude<SecretRequestStatus, 'fulfilled'>, interval }
}

export async function ackSecretRequest(principal: Principal, id: string, pollToken: string) {
  const row = await findPolledRequest(principal, id, pollToken)
  if (row.status === 'pending' || row.status === 'fulfilled') {
    throw new HttpError(409, { error: 'not_delivered', message: 'Poll the response before acknowledging it' })
  }
  if (row.status !== 'delivered') {
    return
  }

  const now = new Date()
  await (await prisma()).secretRequest.updateMany({
    where: { id: row.id, status: 'delivered' },
    data: { ...WIPED_RESPONSE, acked_at: row.acked_at ?? now, closed_at: row.closed_at ?? now },
  })
}

export async function cancelSecretRequest(principal: Principal, id: string, request: FastifyRequest) {
  const row = await settleSecretRequest(await findOwnRequest(principal.user.id, id), request)
  assertAgentBinding(principal, row)

  if (row.status === 'cancelled') {
    return { status: 'cancelled' as const }
  }
  if (row.status !== 'pending' && row.status !== 'fulfilled') {
    throw new HttpError(row.status === 'expired' ? 410 : 409, {
      error: row.status === 'expired' ? 'expired' : 'not_pending',
      status: row.status,
      message: `This secret request is already ${row.status}`,
    })
  }

  const now = new Date()
  const result = await (await prisma()).secretRequest.updateMany({
    where: { id: row.id, status: { in: ['pending', 'fulfilled'] } },
    data: { status: 'cancelled', closed_at: now, ...WIPED_RESPONSE },
  })
  if (result.count !== 1) {
    const current = await reload(row.id)
    if (current.status !== 'cancelled') {
      throw new HttpError(409, { error: 'not_pending', status: current.status })
    }
    return { status: 'cancelled' as const }
  }

  await recordRequestEvent(row, 'request.cancelled', requesterActor(principal, row), { was: row.status }, request)
  return { status: 'cancelled' as const }
}

// ── listing and cleanup ──────────────────────────────────────────────────

export async function listSecretRequests(
  principal: Principal,
  status: SecretRequestStatus | undefined
): Promise<SecretRequestSummary[]> {
  const db = await prisma()
  const now = new Date()
  const due = await db.secretRequest.findMany({
    where: { user_id: principal.user.id, status: { in: ['pending', 'fulfilled'] }, expires_at: { lte: now } },
    take: 500,
  })
  for (const row of due) {
    await settleSecretRequest(row)
  }

  const rows = await db.secretRequest.findMany({
    where: {
      user_id: principal.user.id,
      ...(principal.agent_id ? { requester_agent_id: principal.agent_id } : {}),
      ...(status ? { status } : {}),
    },
    orderBy: [{ created_at: 'desc' }, { id: 'desc' }],
    take: LIST_LIMIT,
  })

  const agentIds = [...new Set(rows.map((row) => row.requester_agent_id))]
  const agents = agentIds.length
    ? await db.agentIdentity.findMany({ where: { id: { in: agentIds } }, select: { id: true, name: true } })
    : []
  const names = new Map(agents.map((agent) => [agent.id, agent.name]))

  return rows.map((row) => ({
    id: row.id,
    code: formatRequestCode(row.code),
    name: row.name,
    reason: row.reason,
    accept: row.accept as SecretRequestAccept,
    fingerprint: row.fingerprint,
    status: row.status as SecretRequestStatus,
    requester: { agent: { id: row.requester_agent_id, name: names.get(row.requester_agent_id) ?? null } },
    response_kind: (row.response_kind as SecretRequestResponseKind | null) ?? null,
    response_size: row.response_size,
    created_at: row.created_at,
    expires_at: row.expires_at,
    opened_at: row.opened_at,
    fulfilled_at: row.fulfilled_at,
    delivered_at: row.delivered_at,
    acked_at: row.acked_at,
    closed_at: row.closed_at,
  }))
}

// Cron: expire due requests, wipe responses whose lease is over, and drop
// finished requests older than the audit retention.
export async function cleanupSecretRequests(now = new Date()) {
  if (config.DISABLE_AUTH) {
    return 0
  }

  const db = await prisma()
  const due = await db.secretRequest.findMany({
    where: {
      OR: [
        { status: { in: ['pending', 'fulfilled'] }, expires_at: { lte: now } },
        {
          status: 'delivered',
          response_ciphertext: { not: null },
          delivered_at: { lte: new Date(now.getTime() - DELIVERY_LEASE_MS) },
        },
      ],
    },
    take: 1000,
  })
  for (const row of due) {
    await settleSecretRequest(row)
  }

  const cutoff = new Date(now.getTime() - config.AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000)
  const purged = await db.secretRequest.deleteMany({
    where: { created_at: { lt: cutoff }, status: { notIn: ['pending', 'fulfilled'] } },
  })

  return due.length + purged.count
}
