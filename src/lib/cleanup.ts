import { markOwnedShareStatus } from './account-shares.js'
import { getPrisma } from './db.js'
import {
  deleteFileSharesByIds,
  listExpiredOrAbandonedFileShares,
} from './file-shares-db.js'
import { deleteFileShareObjects } from './file-storage.js'

export async function cleanupExpiredPastes(): Promise<number> {
  const prisma = getPrisma()
  const pastes = await prisma.paste.findMany({
    where: {
      OR: [
        {
          expires_at: {
            lte: new Date(),
          },
        },
        {
          is_burned: true,
        },
      ],
    },
    select: {
      id: true,
      is_burned: true,
    },
  })

  for (const paste of pastes) {
    await markOwnedShareStatus(
      'paste',
      paste.id,
      paste.is_burned ? 'burned' : 'expired'
    )
  }

  const result = await prisma.paste.deleteMany({
    where: {
      OR: [
        {
          expires_at: {
            lte: new Date(),
          },
        },
        {
          is_burned: true,
        },
      ],
    },
  })

  const now = new Date()
  const incompleteCutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000)
  const fileShares = await listExpiredOrAbandonedFileShares(now, incompleteCutoff)

  for (const share of fileShares) {
    await markOwnedShareStatus(
      'file_share',
      share.id,
      share.is_complete ? 'expired' : 'abandoned'
    )
    await deleteFileShareObjects(share.slug)
  }

  const deletedFileShares = await deleteFileSharesByIds(
    fileShares.map((share) => share.id)
  )

  return result.count + deletedFileShares
}
