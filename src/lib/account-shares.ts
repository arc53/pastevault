import { getPrisma } from './db.js'
import { ensureAccountSystemSchema } from './account-schema.js'

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
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.findFirst({
    where: {
      share_type: shareType,
      resource_id: resourceId,
    },
  })
}

export async function createOwnedPasteRecord(input: {
  user_id: string
  resource_id: string
  slug: string
  expires_at: Date | null
  burn_after_read: boolean
  is_password_protected: boolean
}) {
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
  is_password_protected: boolean
}) {
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
      is_password_protected: input.is_password_protected,
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

  return prisma.ownedShare.update({
    where: { id: share.id },
    data: {
      status,
      deleted_at: deletedAt,
    },
  })
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

export async function listOwnedShares(input: {
  user_id: string
  share_type?: OwnedShareType
  status?: OwnedShareStatus
}) {
  await ensureAccountSystemSchema()
  const prisma = getPrisma()

  return prisma.ownedShare.findMany({
    where: {
      user_id: input.user_id,
      ...(input.share_type ? { share_type: input.share_type } : {}),
      ...(input.status ? { status: input.status } : {}),
    },
    orderBy: {
      created_at: 'desc',
    },
  })
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
