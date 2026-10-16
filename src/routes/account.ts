import { FastifyInstance } from 'fastify'
import {
  canDeleteOwnedShare,
  getOwnedShareForUser,
  listOwnedShares,
  markOwnedShareStatus,
  OWNED_SHARE_STATUSES,
  OWNED_SHARE_TYPES,
} from '../lib/account-shares.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import {
  auditActorFor,
  decodeCursor,
  encodeCursor,
  listAuditEvents,
  listSubjectAuditEvents,
  recordShareEvent,
  toAuditEventResponses,
} from '../lib/audit.js'
import { deleteFileSharesByIds } from '../lib/file-shares-db.js'
import { deleteFileShareObjects } from '../lib/file-storage.js'
import { getPrisma } from '../lib/db.js'
import { requirePrincipal } from '../lib/principal.js'
import {
  accountShareParamsSchema,
  accountSharesQuerySchema,
  auditQuerySchema,
  HttpError,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  AccountShare,
  ListAccountSharesResponse,
  ListAuditEventsResponse,
  ListShareEventsResponse,
  OwnedShareStatus,
  OwnedShareType,
} from '../types/index.js'

function toOwnedShareType(value: string): OwnedShareType {
  if (OWNED_SHARE_TYPES.includes(value as OwnedShareType)) {
    return value as OwnedShareType
  }

  throw new Error(`Unsupported share type: ${value}`)
}

function toOwnedShareStatus(value: string): OwnedShareStatus {
  if (OWNED_SHARE_STATUSES.includes(value as OwnedShareStatus)) {
    return value as OwnedShareStatus
  }

  throw new Error(`Unsupported share status: ${value}`)
}

type OwnedShareRow = Parameters<typeof toAccountShareResponse>[0]

// Recipient agents are looked up once per page; deleted agents show no name.
async function loadRecipientAgentNames(shares: OwnedShareRow[]) {
  const agentIds = [
    ...new Set(
      shares
        .map((share) => share.recipient_agent_id)
        .filter((id): id is string => Boolean(id))
    ),
  ]

  if (agentIds.length === 0) {
    return new Map<string, string>()
  }

  const agents = await getPrisma().agentIdentity.findMany({
    where: { id: { in: agentIds } },
    select: { id: true, name: true },
  })
  return new Map(agents.map((agent) => [agent.id, agent.name]))
}

function decodeCursorParam(cursor: string | undefined) {
  if (cursor === undefined) {
    return null
  }

  const decoded = decodeCursor(cursor)
  if (!decoded) {
    throw new HttpError(400, { error: 'Invalid cursor' })
  }

  return decoded
}

function toAccountShareResponse(share: {
  id: string
  share_type: string
  slug: string
  status: string
  created_at: Date
  expires_at: Date | null
  deleted_at: Date | null
  first_viewed_at: Date | null
  last_viewed_at: Date | null
  view_count: number
  burn_after_read: boolean
  file_count: number | null
  total_size_bytes: string | null
  is_password_protected: boolean
  max_views: number | null
  recipient_fingerprint: string | null
  recipient_agent_id: string | null
}, recipientAgentNames: Map<string, string> = new Map()): AccountShare {
  const shareType = toOwnedShareType(share.share_type)
  const status = toOwnedShareStatus(share.status)

  return {
    id: share.id,
    share_type: shareType,
    slug: share.slug,
    status,
    created_at: share.created_at,
    expires_at: share.expires_at,
    deleted_at: share.deleted_at,
    first_viewed_at: share.first_viewed_at,
    last_viewed_at: share.last_viewed_at,
    view_count: share.view_count,
    burn_after_read: share.burn_after_read,
    file_count: share.file_count,
    total_size_bytes: share.total_size_bytes,
    is_password_protected: share.is_password_protected,
    can_delete: canDeleteOwnedShare(status),
    max_views: share.max_views,
    recipient_fingerprint: share.recipient_fingerprint,
    recipient_agent_name: share.recipient_agent_id
      ? (recipientAgentNames.get(share.recipient_agent_id) ?? null)
      : null,
  }
}

export async function accountRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.setErrorHandler(validationErrorHandler)

  fastify.get<{
    Querystring: {
      share_type?: string
      status?: string
      slug?: string
      limit?: string
      cursor?: string
    }
  }>('/account/shares', async (request, reply) => {
    const principal = await requirePrincipal(request, 'shares:read')
    const query = accountSharesQuerySchema.parse(request.query)
    const { shares, has_more } = await listOwnedShares({
      user_id: principal.user.id,
      share_type: query.share_type,
      status: query.status,
      slug: query.slug,
      limit: query.limit,
      cursor: decodeCursorParam(query.cursor),
    })
    const recipientAgentNames = await loadRecipientAgentNames(shares)

    const response: ListAccountSharesResponse = {
      shares: shares.map((share) => toAccountShareResponse(share, recipientAgentNames)),
      next_cursor: has_more ? encodeCursor(shares[shares.length - 1]!) : null,
    }

    return reply.send(response)
  })

  fastify.get<{
    Params: { shareId: string }
  }>('/account/shares/:shareId/events', async (request, reply) => {
    const principal = await requirePrincipal(request, 'shares:read')
    const { shareId } = accountShareParamsSchema.parse(request.params)
    const share = await getOwnedShareForUser(shareId, principal.user.id)

    if (!share) {
      return reply.code(404).send({ error: 'Tracked share not found' })
    }

    const response: ListShareEventsResponse = {
      events: await toAuditEventResponses(
        await listSubjectAuditEvents(principal.user.id, share.id)
      ),
    }

    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.get<{
    Querystring: { since?: string; limit?: string; cursor?: string; event?: string }
  }>('/account/audit', async (request, reply) => {
    const principal = await requirePrincipal(request, 'audit:read')
    const query = auditQuerySchema.parse(request.query)
    const page = await listAuditEvents({
      user_id: principal.user.id,
      since: query.since,
      event: query.event,
      cursor: decodeCursorParam(query.cursor),
      limit: query.limit,
    })

    const response: ListAuditEventsResponse = {
      events: await toAuditEventResponses(page.events),
      next_cursor: page.next_cursor,
    }

    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.delete<{
    Params: { shareId: string }
  }>('/account/shares/:shareId', async (request, reply) => {
    const principal = await requirePrincipal(request, 'shares:revoke')
    const { shareId } = accountShareParamsSchema.parse(request.params)
    const share = await getOwnedShareForUser(shareId, principal.user.id)

    if (!share) {
      return reply.code(404).send({ error: 'Tracked share not found' })
    }

    const shareStatus = toOwnedShareStatus(share.status)

    if (!canDeleteOwnedShare(shareStatus)) {
      return reply.code(409).send({ error: 'Share is no longer deletable' })
    }

    const shareType = toOwnedShareType(share.share_type)

    if (shareType === 'paste') {
      const prisma = getPrisma()
      await prisma.paste.deleteMany({
        where: {
          id: share.resource_id,
        },
      })
    } else {
      await deleteFileShareObjects(share.slug)
      await deleteFileSharesByIds([share.resource_id])
    }

    const updated = await markOwnedShareStatus(
      shareType,
      share.resource_id,
      'deleted'
    )

    if (!updated) {
      return reply.code(404).send({ error: 'Tracked share not found' })
    }

    await recordShareEvent(updated, 'share.revoked', auditActorFor(principal, updated.user_id), {
      request,
    })

    return reply.send({
      share: toAccountShareResponse(updated, await loadRecipientAgentNames([updated])),
    })
  })
}
