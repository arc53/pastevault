import { prisma } from './db'

export async function cleanupExpiredPastes(): Promise<number> {
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

  return result.count
}