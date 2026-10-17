import { FastifyInstance } from 'fastify'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { config } from '../lib/config.js'
import { requirePrincipal, requireSession } from '../lib/principal.js'
import {
  ackSecretRequest,
  cancelSecretRequest,
  createSecretRequest,
  declineSecretRequest,
  formatRequestCode,
  fulfillSecretRequest,
  getSecretRequestByCode,
  listSecretRequests,
  pollSecretRequest,
} from '../lib/secret-requests.js'
import {
  createSecretRequestSchema,
  fulfillSecretRequestSchema,
  HttpError,
  listSecretRequestsQuerySchema,
  pollSecretRequestSchema,
  secretRequestCodeParamsSchema,
  secretRequestParamsSchema,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  CreateSecretRequestRequest,
  CreateSecretRequestResponse,
  FulfillSecretRequestRequest,
  ListSecretRequestsResponse,
} from '../types/index.js'

// The fulfilment body carries the sealed response as base64url (4/3 of its
// size) plus a little JSON; MAX_SECRET_REQUEST_BYTES limits the decoded
// ciphertext itself.
const FULFILL_BODY_LIMIT = Math.ceil((config.MAX_SECRET_REQUEST_BYTES * 4) / 3) + 16 * 1024

// Secret requests (spec §2.6). Registered only when accounts are enabled.
export async function secretRequestsRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.setErrorHandler(validationErrorHandler)

  fastify.post<{
    Body: CreateSecretRequestRequest
  }>('/secret-requests', async (request, reply) => {
    const principal = await requirePrincipal(request, 'requests:create')
    const body = createSecretRequestSchema.parse(request.body)
    const { row, pollToken } = await createSecretRequest(principal, body, request)

    const code = formatRequestCode(row.code)
    const response: CreateSecretRequestResponse = {
      id: row.id,
      code,
      url_path: `/r/${code}`,
      expires_at: row.expires_at,
      poll_token: pollToken,
      interval: row.poll_interval,
    }
    return reply.code(201).header('Cache-Control', 'no-store').send(response)
  })

  // The human's side is session-only: an API token (an agent) can never
  // read the request page data, answer or decline a request.
  fastify.get<{
    Params: { code: string }
  }>('/secret-requests/by-code/:code', async (request, reply) => {
    const principal = await requireSession(request)
    const { code } = secretRequestCodeParamsSchema.parse(request.params)
    const response = await getSecretRequestByCode(principal, code, request)
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.post<{
    Params: { requestId: string }
    Body: FulfillSecretRequestRequest
  }>('/secret-requests/:requestId/fulfill', { bodyLimit: FULFILL_BODY_LIMIT }, async (request, reply) => {
    const principal = await requireSession(request)
    // JSON only: a cross-site form or text/plain POST is not a "simple"
    // request a browser would send without a CORS preflight.
    if (!/^application\/json\s*(;|$)/i.test(request.headers['content-type'] ?? '')) {
      throw new HttpError(415, { error: 'unsupported_media_type', message: 'Send the response as application/json' })
    }
    const { requestId } = secretRequestParamsSchema.parse(request.params)
    const body = fulfillSecretRequestSchema.parse(request.body)
    const response = await fulfillSecretRequest(principal, requestId, body, request)
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.post<{
    Params: { requestId: string }
  }>('/secret-requests/:requestId/decline', async (request, reply) => {
    const principal = await requireSession(request)
    const { requestId } = secretRequestParamsSchema.parse(request.params)
    const response = await declineSecretRequest(principal, requestId, request)
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.post<{
    Params: { requestId: string }
    Body: { poll_token: string }
  }>('/secret-requests/:requestId/poll', async (request, reply) => {
    const principal = await requirePrincipal(request, 'requests:create')
    const { requestId } = secretRequestParamsSchema.parse(request.params)
    const { poll_token } = pollSecretRequestSchema.parse(request.body)
    const response = await pollSecretRequest(principal, requestId, poll_token, request)
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.post<{
    Params: { requestId: string }
    Body: { poll_token: string }
  }>('/secret-requests/:requestId/ack', async (request, reply) => {
    const principal = await requirePrincipal(request, 'requests:create')
    const { requestId } = secretRequestParamsSchema.parse(request.params)
    const { poll_token } = pollSecretRequestSchema.parse(request.body)
    await ackSecretRequest(principal, requestId, poll_token)
    return reply.code(204).header('Cache-Control', 'no-store').send()
  })

  // The requester (a token with requests:create) or the account's session.
  fastify.delete<{
    Params: { requestId: string }
  }>('/secret-requests/:requestId', async (request, reply) => {
    const principal = await requirePrincipal(request, 'requests:create')
    const { requestId } = secretRequestParamsSchema.parse(request.params)
    const response = await cancelSecretRequest(principal, requestId, request)
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.get<{
    Querystring: { status?: string }
  }>('/account/secret-requests', async (request, reply) => {
    const principal = await requirePrincipal(request, 'requests:create')
    const { status } = listSecretRequestsQuerySchema.parse(request.query)
    const response: ListSecretRequestsResponse = {
      requests: await listSecretRequests(principal, status),
    }
    return reply.header('Cache-Control', 'no-store').send(response)
  })
}
