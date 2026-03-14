import { getPrisma } from './db'
import {
  deleteFileSharesByIds,
  listExpiredOrAbandonedFileShares,
} from './file-shares-db'
import { deleteFileShareObjects } from './file-storage'

export async function cleanupExpiredPastes(): Promise<number> {
  const prisma = getPrisma()

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
    await deleteFileShareObjects(share.slug)
  }

  const deletedFileShares = await deleteFileSharesByIds(
    fileShares.map((share) => share.id)
  )

  return result.count + deletedFileShares
}
