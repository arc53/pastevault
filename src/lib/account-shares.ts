import { getPrisma } from './db.js'
import { ensureAccountSystemSchema } from './account-schema.js'
import { cursorWhere, recordShareEvent, SYSTEM_ACTOR } from './audit.js'
import { config } from './config.js'

export const OWNED_SHARE_TYPES = ['paste', 'file_share'] as const
export type OwnedShareType = (typeof OWNED_SHARE_TYPES)[number]

export const OWNED_SHARE_STATUSES = [
  'uploading',
  'active',
  'burned',
  'expired',
  'deleted',
  'abandoned',
] as const
export type OwnedShareStatus = (typeof OWNED_SHARE_STATUSES)[number]

export function canDeleteOwnedShare(status: OwnedShareStatus) {
  return status === 'active' || status === 'uploading'
}

async function findOwnedShareByResource(
  shareType: OwnedShareType,
  resourceId: string
) {
  if (config.DISABLE_AUTH) {
    return null
  }

  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.findFirst({
    where: {
      share_type: shareType,
      resource_id: resourceId,
    },
  })
}

// Sharing options mirrored onto the owned-share record.
export interface OwnedShareOptions {
  max_views: number | null
  recipient_fingerprint: string | null
  recipient_agent_id: string | null
  created_via_token_id: string | null
}

export async function createOwnedPasteRecord(input: {
  user_id: string
  resource_id: string
  slug: string
  expires_at: Date | null
  burn_after_read: boolean
  is_password_protected: boolean
} & OwnedShareOptions) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.create({
    data: {
      user_id: input.user_id,
      share_type: 'paste',
      resource_id: input.resource_id,
      slug: input.slug,
      status: 'active',
      expires_at: input.expires_at,
      burn_after_read: input.burn_after_read,
      is_password_protected: input.is_password_protected,
      max_views: input.max_views,
      recipient_fingerprint: input.recipient_fingerprint,
      recipient_agent_id: input.recipient_agent_id,
      created_via_token_id: input.created_via_token_id,
    },
  })
}

export async function createOwnedFileShareRecord(input: {
  user_id: string
  resource_id: string
  slug: string
  expires_at: Date | null
  file_count: number
  total_size_bytes: number
  burn_after_read: boolean
  is_password_protected: boolean
} & OwnedShareOptions) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.create({
    data: {
      user_id: input.user_id,
      share_type: 'file_share',
      resource_id: input.resource_id,
      slug: input.slug,
      status: 'uploading',
      expires_at: input.expires_at,
      file_count: input.file_count,
      total_size_bytes: String(input.total_size_bytes),
      burn_after_read: input.burn_after_read,
      is_password_protected: input.is_password_protected,
      max_views: input.max_views,
      recipient_fingerprint: input.recipient_fingerprint,
      recipient_agent_id: input.recipient_agent_id,
      created_via_token_id: input.created_via_token_id,
    },
  })
}

export async function markOwnedShareStatus(
  shareType: OwnedShareType,
  resourceId: string,
  status: OwnedShareStatus
) {
  const share = await findOwnedShareByResource(shareType, resourceId)
  if (!share) {
    return null
  }

  const prisma = getPrisma()
  const deletedAt =
    status === 'active' ? null : status === 'uploading' ? null : new Date()

  const updated = await prisma.ownedShare.update({
    where: { id: share.id },
    data: {
      status,
      deleted_at: deletedAt,
    },
  })

  // Expiry is discovered lazily (on access) or by the cleanup job, so it is
  // attributed to the system.
  if (status === 'expired' && share.status !== 'expired') {
    await recordShareEvent(updated, 'share.expired', SYSTEM_ACTOR)
  }

  return updated
}

export async function recordOwnedShareView(input: {
  share_type: OwnedShareType
  resource_id: string
  next_status?: OwnedShareStatus
}) {
  const share = await findOwnedShareByResource(input.share_type, input.resource_id)
  if (!share) {
    return null
  }

  const prisma = getPrisma()
  const viewedAt = new Date()

  return prisma.ownedShare.update({
    where: { id: share.id },
    data: {
      view_count: {
        increment: 1,
      },
      first_viewed_at: share.first_viewed_at ?? viewedAt,
      last_viewed_at: viewedAt,
      ...(input.next_status
        ? {
            status: input.next_status,
            deleted_at:
              input.next_status === 'active' || input.next_status === 'uploading'
                ? null
                : viewedAt,
          }
        : {}),
    },
  })
}

// Newest first. Without a limit every matching share is returned (what the
// web account page expects); with one, `next_cursor` continues the listing.
export async function listOwnedShares(input: {
  user_id: string
  share_type?: OwnedShareType
  status?: OwnedShareStatus
  slug?: string
  limit?: number
  cursor?: { created_at: Date; id: string } | null
}) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  const rows = await prisma.ownedShare.findMany({
    where: {
      user_id: input.user_id,
      ...(input.share_type ? { share_type: input.share_type } : {}),
      ...(input.status ? { status: input.status } : {}),
      ...(input.slug ? { slug: input.slug } : {}),
      AND: [cursorWhere(input.cursor ?? null)],
    },
    orderBy: [{ created_at: 'desc' }, { id: 'desc' }],
    ...(input.limit ? { take: input.limit + 1 } : {}),
  })

  if (!input.limit || rows.length <= input.limit) {
    return { shares: rows, has_more: false }
  }

  return { shares: rows.slice(0, input.limit), has_more: true }
}

export async function getOwnedShareForUser(id: string, userId: string) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.findFirst({
    where: {
      id,
      user_id: userId,
    },
  })
}
