import { isIPv4, isIPv6 } from 'node:net'
import type { FastifyBaseLogger, FastifyRequest } from 'fastify'
import { ensureAccountSystemSchema } from './account-schema.js'
import { config } from './config.js'
import { getPrisma } from './db.js'
import type { Principal } from './principal.js'

export const AUDIT_SUBJECT_TYPES = [
  'paste',
  'file_share',
  'secret_request',
  'agent',
  'token',
] as const
export type AuditSubjectType = (typeof AUDIT_SUBJECT_TYPES)[number]

export const AUDIT_EVENTS = [
  'share.created',
  'share.viewed',
  'share.burned',
  'share.download_granted',
  'share.access_denied',
  'share.expired',
  'share.revoked',
  'request.created',
  'request.opened',
  'request.fulfilled',
  'request.delivered',
  'request.declined',
  'request.expired',
  'request.cancelled',
  'agent.registered',
  'agent.revoked',
  'token.created',
  'token.revoked',
] as const
export type AuditEventName = (typeof AUDIT_EVENTS)[number]

export type AuditActorKind = 'owner' | 'recipient' | 'anonymous' | 'system'

export interface AuditActor {
  kind: AuditActorKind
  token_id?: string | null
  agent_id?: string | null
}

export const SYSTEM_ACTOR: AuditActor = { kind: 'system' }

const MAX_CLIENT_LENGTH = 64

// The owner's own requests are attributed to their token/agent. Anyone else is
// anonymous: the log belongs to the owner and must not identify other accounts.
export function auditActorFor(principal: Principal | null, ownerUserId: string): AuditActor {
  if (principal && principal.user.id === ownerUserId) {
    return {
      kind: 'owner',
      token_id: principal.token_id,
      agent_id: principal.agent_id,
    }
  }

  return { kind: 'anonymous' }
}

// A share sealed to an agent of the owner's account, opened by that account
// (recipient auth passed). Attributed to the agent the share was sealed to.
export function recipientActor(principal: Principal, agentId: string | null): AuditActor {
  return { kind: 'recipient', token_id: principal.token_id, agent_id: agentId }
}

// Client family only, never the full User-Agent string.
export function describeClient(userAgent: string | undefined) {
  if (!userAgent) {
    return null
  }

  const cli = /^pastevault(?:-cli)?\/([0-9A-Za-z.+-]{1,40})(?:\s|$)/.exec(userAgent)
  if (cli) {
    return `pastevault-cli/${cli[1]}`.slice(0, MAX_CLIENT_LENGTH)
  }

  return /^Mozilla\//.test(userAgent) ? 'browser' : 'other'
}

function expandIPv6(address: string) {
  const [head, tail] = address.split('::') as [string, string | undefined]
  const headGroups = head ? head.split(':') : []
  const tailGroups = tail ? tail.split(':') : []
  const missing = 8 - headGroups.length - tailGroups.length
  const groups =
    tail === undefined
      ? headGroups
      : [...headGroups, ...Array<string>(Math.max(missing, 0)).fill('0'), ...tailGroups]
  return groups.map((group) => group.toLowerCase().replace(/^0+(?=.)/, ''))
}

// IPv4 /24 or IPv6 /48, as network notation.
export function truncateIp(address: string | undefined) {
  if (!address) {
    return null
  }

  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)
  const candidate = mapped ? mapped[1]! : address.split('%')[0]!

  if (isIPv4(candidate)) {
    const [a, b, c] = candidate.split('.')
    return `${a}.${b}.${c}.0/24`
  }

  if (isIPv6(candidate) && !candidate.includes('.')) {
    return `${expandIPv6(candidate).slice(0, 3).join(':')}::/48`
  }

  return null
}

export interface AuditEventInput {
  user_id: string
  subject_type: AuditSubjectType
  subject_id?: string | null
  slug?: string | null
  event: AuditEventName
  actor: AuditActor
  details?: Record<string, unknown>
  // Source of the client family and, when AUDIT_IP_MODE=truncated, the network.
  request?: FastifyRequest
}

// Best effort, like owned-share metrics: an audit failure is logged and never
// fails the request that caused it. A no-op when accounts are disabled.
export async function recordAuditEvent(input: AuditEventInput, log?: FastifyBaseLogger) {
  if (config.DISABLE_AUTH) {
    return
  }

  try {
    await ensureAccountSystemSchema()
    const userAgent = input.request?.headers['user-agent']

    await getPrisma().auditEvent.create({
      data: {
        user_id: input.user_id,
        subject_type: input.subject_type,
        subject_id: input.subject_id ?? null,
        slug: input.slug ?? null,
        event: input.event,
        actor_kind: input.actor.kind,
        actor_token_id: input.actor.token_id ?? null,
        actor_agent_id: input.actor.agent_id ?? null,
        client: input.request ? describeClient(userAgent) : null,
        ip_prefix:
          input.request && config.AUDIT_IP_MODE === 'truncated'
            ? truncateIp(input.request.ip)
            : null,
        details: input.details ? JSON.stringify(input.details) : null,
      },
    })
  } catch (error: unknown) {
    const logger = log ?? input.request?.log
    if (logger) {
      logger.error({ err: error, event: input.event }, 'Failed to record audit event')
    } else {
      console.error('Failed to record audit event', input.event, error)
    }
  }
}

export function auditSubjectForShareType(shareType: string): AuditSubjectType {
  return shareType === 'file_share' ? 'file_share' : 'paste'
}

// Records an event against an owned share (OwnedShare row).
export function recordShareEvent(
  share: { id: string; user_id: string; share_type: string; slug: string },
  event: AuditEventName,
  actor: AuditActor,
  options: { details?: Record<string, unknown>; request?: FastifyRequest } = {}
) {
  return recordAuditEvent({
    user_id: share.user_id,
    subject_type: auditSubjectForShareType(share.share_type),
    subject_id: share.id,
    slug: share.slug,
    event,
    actor,
    details: options.details,
    request: options.request,
  })
}

// Views of shares without a view limit are unbounded, so they are folded into
// one share.viewed event per actor per window instead of one row per GET.
export const VIEW_COALESCE_WINDOW_MS = 10 * 60 * 1000

type ShareRef = { id: string; user_id: string; share_type: string; slug: string }

// Folds repeated events by the same actor (actor_kind and actor_token_id)
// within VIEW_COALESCE_WINDOW_MS into the latest one: `merge` builds its new
// details from the previous ones. Unbounded events (views of unlimited
// shares, denied attempts) then cost one row per actor per window.
async function recordCoalescedShareEvent(
  share: ShareRef,
  event: AuditEventName,
  actor: AuditActor,
  merge: (previous: Record<string, unknown> | null) => Record<string, unknown>,
  request?: FastifyRequest,
  // Only events whose details pass this are folded into (e.g. same reason).
  sameGroup?: (details: Record<string, unknown> | null) => boolean
) {
  if (config.DISABLE_AUTH) {
    return
  }

  try {
    await ensureAccountSystemSchema()
    const prisma = getPrisma()
    const candidates = await prisma.auditEvent.findMany({
      where: {
        user_id: share.user_id,
        subject_id: share.id,
        event,
        actor_kind: actor.kind,
        actor_token_id: actor.token_id ?? null,
        created_at: { gte: new Date(Date.now() - VIEW_COALESCE_WINDOW_MS) },
      },
      orderBy: [{ created_at: 'desc' }, { id: 'desc' }],
      take: 20,
    })
    const recent = candidates.find((candidate) => !sameGroup || sameGroup(parseDetails(candidate.details)))

    if (recent) {
      // Approximate under concurrency (read-modify-write); it's a counter in a
      // metadata log, not an access control.
      await prisma.auditEvent.update({
        where: { id: recent.id },
        data: { details: JSON.stringify(merge(parseDetails(recent.details))) },
      })
      return
    }
  } catch (error: unknown) {
    const logger = request?.log ?? console
    logger.error({ err: error, event }, 'Failed to coalesce audit event')
  }

  return recordShareEvent(share, event, actor, { details: merge(null), request })
}

// share.viewed. View-limited shares log every view (at most max_views rows).
// Unlimited shares extend the actor's latest share.viewed from the last
// VIEW_COALESCE_WINDOW_MS when there is one: details.view becomes the latest
// view number and details.views counts the views folded into the event.
export async function recordShareView(
  share: ShareRef,
  actor: AuditActor,
  view: { view: number; max_views: number | null },
  request?: FastifyRequest
) {
  if (view.max_views !== null || config.DISABLE_AUTH) {
    return recordShareEvent(share, 'share.viewed', actor, { details: view, request })
  }

  return recordCoalescedShareEvent(
    share,
    'share.viewed',
    actor,
    (previous) =>
      previous
        ? {
            ...view,
            views: (typeof previous.views === 'number' ? previous.views : 1) + 1,
            last_viewed_at: new Date(),
          }
        : { ...view, views: 1 },
    request
  )
}

// share.access_denied: a consuming GET of a sealed share without the
// recipient's credentials. No view was consumed. Repeated attempts by the same
// actor for the same reason are folded: details.attempts counts them.
export async function recordShareAccessDenied(
  share: ShareRef,
  actor: AuditActor,
  reason: string,
  request?: FastifyRequest
) {
  return recordCoalescedShareEvent(
    share,
    'share.access_denied',
    actor,
    (previous) =>
      previous
        ? {
            reason,
            attempts: (typeof previous.attempts === 'number' ? previous.attempts : 1) + 1,
            last_attempt_at: new Date(),
          }
        : { reason, attempts: 1 },
    request,
    (details) => details?.reason === reason
  )
}

export async function purgeAuditEventsOlderThan(cutoff: Date) {
  if (config.DISABLE_AUTH) {
    return 0
  }

  await ensureAccountSystemSchema()
  const result = await getPrisma().auditEvent.deleteMany({
    where: { created_at: { lt: cutoff } },
  })
  return result.count
}

const AUDIT_CURSOR_PATTERN = /^[A-Za-z0-9_-]{1,512}$/

// Opaque keyset cursor over (created_at DESC, id DESC).
export function encodeCursor(row: { created_at: Date; id: string }) {
  return Buffer.from(`${row.created_at.toISOString()}|${row.id}`).toString('base64url')
}

export function decodeCursor(cursor: string | undefined) {
  if (!cursor || !AUDIT_CURSOR_PATTERN.test(cursor)) {
    return null
  }

  const [createdAt, id] = Buffer.from(cursor, 'base64url').toString('utf8').split('|')
  const date = createdAt ? new Date(createdAt) : null
  if (!date || Number.isNaN(date.getTime()) || !id) {
    return null
  }

  return { created_at: date, id }
}

export function cursorWhere(cursor: { created_at: Date; id: string } | null) {
  if (!cursor) {
    return {}
  }

  return {
    OR: [
      { created_at: { lt: cursor.created_at } },
      { created_at: cursor.created_at, id: { lt: cursor.id } },
    ],
  }
}

export async function listAuditEvents(input: {
  user_id: string
  since?: Date
  event?: string
  cursor: { created_at: Date; id: string } | null
  limit: number
}) {
  await ensureAccountSystemSchema()
  const rows = await getPrisma().auditEvent.findMany({
    where: {
      user_id: input.user_id,
      ...(input.since ? { created_at: { gte: input.since } } : {}),
      ...(input.event ? { event: input.event } : {}),
      AND: [cursorWhere(input.cursor)],
    },
    orderBy: [{ created_at: 'desc' }, { id: 'desc' }],
    take: input.limit + 1,
  })

  const page = rows.slice(0, input.limit)
  return {
    events: page,
    next_cursor: rows.length > input.limit ? encodeCursor(page[page.length - 1]!) : null,
  }
}

export async function listSubjectAuditEvents(userId: string, subjectId: string) {
  await ensureAccountSystemSchema()
  return getPrisma().auditEvent.findMany({
    where: { user_id: userId, subject_id: subjectId },
    orderBy: [{ created_at: 'asc' }, { id: 'asc' }],
    take: 500,
  })
}

type AuditEventRow = Awaited<ReturnType<typeof listSubjectAuditEvents>>[number]

function parseDetails(details: string | null) {
  if (!details) {
    return null
  }

  try {
    return JSON.parse(details) as Record<string, unknown>
  } catch {
    return null
  }
}

// API shape. Agent names are looked up once per page.
export async function toAuditEventResponses(rows: AuditEventRow[]) {
  const agentIds = [
    ...new Set(rows.map((row) => row.actor_agent_id).filter((id): id is string => Boolean(id))),
  ]
  const agents = agentIds.length
    ? await getPrisma().agentIdentity.findMany({
        where: { id: { in: agentIds } },
        select: { id: true, name: true },
      })
    : []
  const agentsById = new Map(agents.map((agent) => [agent.id, agent]))

  return rows.map((row) => ({
    id: row.id,
    subject_type: row.subject_type,
    subject_id: row.subject_id,
    slug: row.slug,
    event: row.event,
    actor_kind: row.actor_kind,
    actor_agent: row.actor_agent_id
      ? (agentsById.get(row.actor_agent_id) ?? { id: row.actor_agent_id, name: null })
      : null,
    actor_token_id: row.actor_token_id,
    client: row.client,
    ip_prefix: row.ip_prefix,
    created_at: row.created_at,
    details: parseDetails(row.details),
  }))
}
