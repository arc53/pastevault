import { FastifyInstance, FastifyRequest } from 'fastify'
import { auth } from '../lib/auth.js'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'

function getRequestOrigin(request: FastifyRequest) {
  const forwardedProto = request.headers['x-forwarded-proto']
  const protocol =
    typeof forwardedProto === 'string' && forwardedProto.length > 0
      ? forwardedProto.split(',')[0]!.trim()
      : request.protocol

  return `${protocol}://${request.headers.host}`
}

function buildRequestBody(request: FastifyRequest) {
  if (request.method === 'GET' || request.method === 'HEAD') {
    return undefined
  }

  const body = request.body

  if (body === undefined || body === null) {
    return undefined
  }

  if (
    typeof body === 'string' ||
    body instanceof ArrayBuffer
  ) {
    return body
  }

  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
  }

  return JSON.stringify(body)
}

async function handleAuthRequest(request: FastifyRequest) {
  const url = new URL(request.url, getRequestOrigin(request))
  const headers = new Headers()

  for (const [key, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) {
      for (const entry of value) {
        headers.append(key, entry)
      }
      continue
    }

    if (value !== undefined) {
      headers.set(key, value)
    }
  }

  if (!headers.has('content-type') && request.body && typeof request.body === 'object') {
    headers.set('content-type', 'application/json')
  }

  return auth.handler(
    new Request(url, {
      method: request.method,
      headers,
      body: buildRequestBody(request),
      duplex: 'half',
    })
  )
}

export async function authRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.route({
    method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    url: '/auth',
    handler: async (request, reply) => {
      const response = await handleAuthRequest(request)

      reply.code(response.status)
      const setCookie =
        'getSetCookie' in response.headers
          ? response.headers.getSetCookie()
          : []

      for (const value of setCookie) {
        reply.header('set-cookie', value)
      }

      response.headers.forEach((value, key) => {
        if (key.toLowerCase() === 'set-cookie') {
          return
        }
        reply.header(key, value)
      })

      const body = await response.text()
      return reply.send(body)
    },
  })

  fastify.route({
    method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    url: '/auth/*',
    handler: async (request, reply) => {
      const response = await handleAuthRequest(request)

      reply.code(response.status)
      const setCookie =
        'getSetCookie' in response.headers
          ? response.headers.getSetCookie()
          : []

      for (const value of setCookie) {
        reply.header('set-cookie', value)
      }

      response.headers.forEach((value, key) => {
        if (key.toLowerCase() === 'set-cookie') {
          return
        }
        reply.header(key, value)
      })

      const body = await response.text()
      return reply.send(body)
    },
  })
}
