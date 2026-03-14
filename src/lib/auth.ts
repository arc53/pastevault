import { betterAuth } from 'better-auth'
import { prismaAdapter } from 'better-auth/adapters/prisma'
import { username } from 'better-auth/plugins'
import { config } from './config.js'
import { getPrisma } from './db.js'

function splitOrigins(value?: string) {
  if (!value) {
    return []
  }

  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
}

function resolveAuthBaseURL() {
  const explicitBaseUrl = process.env.BETTER_AUTH_URL || config.BETTER_AUTH_URL

  if (explicitBaseUrl) {
    return explicitBaseUrl
  }

  const port = process.env.PORT || String(config.PORT)
  return `http://localhost:${port}/api/auth`
}

function resolveTrustedOrigins() {
  const origins = new Set<string>()

  for (const origin of splitOrigins(
    process.env.BETTER_AUTH_TRUSTED_ORIGINS || config.BETTER_AUTH_TRUSTED_ORIGINS
  )) {
    origins.add(origin)
  }

  const corsOrigin = process.env.CORS_ORIGIN || config.CORS_ORIGIN
  if (corsOrigin && corsOrigin !== '*') {
    for (const origin of splitOrigins(corsOrigin)) {
      origins.add(origin)
    }
  }

  origins.add(new URL(resolveAuthBaseURL()).origin)

  if (config.NODE_ENV !== 'production') {
    const currentPort = process.env.PORT || String(config.PORT)
    origins.add(`http://localhost:${currentPort}`)
    origins.add('http://localhost:3001')
    origins.add('http://localhost:3002')
    origins.add(`http://127.0.0.1:${currentPort}`)
    origins.add('http://127.0.0.1:3001')
    origins.add('http://127.0.0.1:3002')
  }

  return [...origins]
}

export const auth = betterAuth({
  appName: 'PasteVault',
  baseURL: resolveAuthBaseURL(),
  trustedOrigins: resolveTrustedOrigins(),
  database: prismaAdapter(getPrisma(), {
    provider: config.DATABASE_PROVIDER,
    usePlural: false,
  }),
  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
  },
  plugins: [username()],
})
