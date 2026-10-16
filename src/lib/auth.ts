import { betterAuth } from 'better-auth'
import { prismaAdapter } from 'better-auth/adapters/prisma'
import { bearer, deviceAuthorization, username } from 'better-auth/plugins'
import { config } from './config.js'
import { getPrisma } from './db.js'
import { resolveAuthBaseURL, resolveTrustedOrigins, splitOrigins } from './origins.js'

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
    disableSignUp: config.DISABLE_SIGNUP,
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
