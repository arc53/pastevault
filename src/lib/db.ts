import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3'
import { PrismaPg } from '@prisma/adapter-pg'
import { PrismaClient } from '@prisma/client'
import { config } from './config.js'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
  prismaCacheKey: string | undefined
}

function resolveDatabaseSslMode(url: URL) {
  const configuredSslMode = process.env.DATABASE_SSL_MODE || config.DATABASE_SSL_MODE
  if (configuredSslMode) {
    return configuredSslMode
  }

  if (url.hostname.toLowerCase().includes('neon.tech')) {
    return 'require'
  }

  return undefined
}

function normalizeDatabaseUrl(provider: 'postgresql' | 'sqlite', url: string) {
  if (provider !== 'postgresql') {
    return url
  }

  let parsedUrl: URL

  try {
    parsedUrl = new URL(url)
  } catch {
    return url
  }

  if (parsedUrl.searchParams.has('sslmode')) {
    return parsedUrl.toString()
  }

  const sslMode = resolveDatabaseSslMode(parsedUrl)
  if (!sslMode) {
    return url
  }

  parsedUrl.searchParams.set('sslmode', sslMode)
  return parsedUrl.toString()
}

function resolveDatabaseProvider() {
  return process.env.DATABASE_PROVIDER === 'postgresql'
    ? 'postgresql'
    : config.DATABASE_PROVIDER
}

export function resolveDatabaseUrl() {
  const provider = resolveDatabaseProvider()
  const url = process.env.DATABASE_URL || config.DATABASE_URL

  return normalizeDatabaseUrl(provider, url)
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
