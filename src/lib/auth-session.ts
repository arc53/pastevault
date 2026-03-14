import type { FastifyRequest } from 'fastify'
import { fromNodeHeaders } from 'better-auth/node'
import { auth } from './auth.js'

export async function getOptionalAuthSession(request: FastifyRequest) {
  try {
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
