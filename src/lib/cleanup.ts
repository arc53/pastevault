import { getPrisma } from './db'

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

  return result.count
}
