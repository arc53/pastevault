import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3'
import { PrismaPg } from '@prisma/adapter-pg'
import { PrismaClient } from '@prisma/client'
import { config } from './config.js'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
  prismaCacheKey: string | undefined
}

function resolveDatabaseProvider() {
  return process.env.DATABASE_PROVIDER === 'postgresql'
    ? 'postgresql'
    : config.DATABASE_PROVIDER
}

function resolveDatabaseUrl() {
  return process.env.DATABASE_URL || config.DATABASE_URL
}

function createPrismaClient() {
  const provider = resolveDatabaseProvider()
  const url = resolveDatabaseUrl()

  const adapter =
    provider === 'postgresql'
      ? new PrismaPg({ connectionString: url })
      : new PrismaBetterSqlite3({ url })

  return {
    cacheKey: `${provider}:${url}`,
    client: new PrismaClient({
      adapter,
      log: ['query'],
    }),
  }
}

export function getPrisma() {
  const { cacheKey, client } = createPrismaClient()

  if (globalForPrisma.prisma && globalForPrisma.prismaCacheKey === cacheKey) {
    return globalForPrisma.prisma
  }

  if (globalForPrisma.prisma) {
    void globalForPrisma.prisma.$disconnect().catch(() => undefined)
  }

  globalForPrisma.prisma = client
  globalForPrisma.prismaCacheKey = cacheKey

  return client
}
