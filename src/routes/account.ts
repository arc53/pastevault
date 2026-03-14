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
import { requireAuthSession } from '../lib/auth-session.js'
import { deleteFileSharesByIds } from '../lib/file-shares-db.js'
import { deleteFileShareObjects } from '../lib/file-storage.js'
import { getPrisma } from '../lib/db.js'
import {
  accountShareParamsSchema,
  accountSharesQuerySchema,
} from '../lib/validation.js'
import {
  AccountShare,
  ListAccountSharesResponse,
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
}): AccountShare {
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
  }
}

export async function accountRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.get<{
    Querystring: {
      share_type?: string
      status?: string
    }
  }>('/account/shares', async (request, reply) => {
    const session = await requireAuthSession(request)
    if (!session) {
      return reply.code(401).send({ error: 'Authentication required' })
    }

    const query = accountSharesQuerySchema.parse(request.query)
    const shares = await listOwnedShares({
      user_id: session.user.id,
      share_type: query.share_type,
      status: query.status,
    })

    const response: ListAccountSharesResponse = {
      shares: shares.map(toAccountShareResponse),
    }

    return reply.send(response)
  })

  fastify.delete<{
    Params: { shareId: string }
  }>('/account/shares/:shareId', async (request, reply) => {
    const session = await requireAuthSession(request)
    if (!session) {
      return reply.code(401).send({ error: 'Authentication required' })
    }

    const { shareId } = accountShareParamsSchema.parse(request.params)
    const share = await getOwnedShareForUser(shareId, session.user.id)

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

    return reply.send({
      share: toAccountShareResponse(updated),
    })
  })
}
