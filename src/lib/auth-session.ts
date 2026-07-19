import type { FastifyRequest } from 'fastify'
import { config } from './config.js'

export async function getOptionalAuthSession(request: FastifyRequest) {
  if (config.DISABLE_AUTH) {
    return null
  }

  try {
    const [{ fromNodeHeaders }, { auth }] = await Promise.all([
      import('better-auth/node'),
      import('./auth.js'),
    ])
    return await auth.api.getSession({
      headers: fromNodeHeaders(request.raw.headers),
    })
  } catch {
    return null
  }
}

export async function requireAuthSession(request: FastifyRequest) {
  const session = await getOptionalAuthSession(request)

  if (!session) {
    return null
  }

  return session
}
