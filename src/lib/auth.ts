import { betterAuth } from 'better-auth'
import { prismaAdapter } from 'better-auth/adapters/prisma'
import { bearer, deviceAuthorization, username } from 'better-auth/plugins'
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

function joinURLPath(base: string, relativePath: string) {
  const url = new URL(base)
  const normalizedBasePath = url.pathname.replace(/\/+$/, '')
  const normalizedRelativePath = relativePath.replace(/^\/+/, '')

  url.pathname = `${normalizedBasePath}/${normalizedRelativePath}`.replace(/\/{2,}/g, '/')
  url.search = ''
  url.hash = ''

  return url.toString()
}

function resolvePublicAppURL() {
  const explicitPublicUrl = process.env.PASTEVAULT_PUBLIC_URL?.trim()
  if (explicitPublicUrl) {
    return explicitPublicUrl
  }

  const authBaseOrigin = new URL(resolveAuthBaseURL()).origin
  const candidateOrigins = [
    ...splitOrigins(
      process.env.BETTER_AUTH_TRUSTED_ORIGINS || config.BETTER_AUTH_TRUSTED_ORIGINS
    ),
    ...splitOrigins(process.env.CORS_ORIGIN || config.CORS_ORIGIN),
  ]

  for (const candidate of candidateOrigins) {
    if (
      candidate === '*' ||
      candidate === authBaseOrigin ||
      candidate.startsWith(`${authBaseOrigin}/`)
    ) {
      continue
    }

    try {
      if (!new URL(candidate).hostname.startsWith('api.')) {
        return candidate
      }
    } catch {
      return candidate
    }
  }

  for (const candidate of candidateOrigins) {
    if (candidate !== '*') {
      return candidate
    }
  }

  const authBaseURL = new URL(resolveAuthBaseURL())
  authBaseURL.pathname = authBaseURL.pathname.replace(/\/api\/auth\/?$/, '') || '/'
  authBaseURL.search = ''
  authBaseURL.hash = ''

  if (authBaseURL.hostname.startsWith('api.')) {
    authBaseURL.hostname = authBaseURL.hostname.slice(4)
  }

  return authBaseURL.toString()
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
  plugins: [
    username(),
    bearer(),
    deviceAuthorization({
      validateClient: (clientId) => clientId === 'pastevault-cli',
      verificationUri: joinURLPath(resolvePublicAppURL(), '/device'),
    }),
  ],
})
