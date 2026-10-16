import { FastifyInstance } from 'fastify'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import { listAgents, registerAgent, revokeAgent, toAgentSummary } from '../lib/agents.js'
import { requirePrincipal } from '../lib/principal.js'
import {
  agentParamsSchema,
  createAgentSchema,
  listAgentsQuerySchema,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  CreateAgentRequest,
  CreateAgentResponse,
  ListAgentsResponse,
  RevokeAgentResponse,
} from '../types/index.js'

// Agent identities (spec §2.3). Registered only when accounts are enabled.
export async function agentsRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.setErrorHandler(validationErrorHandler)

  fastify.post<{
    Body: CreateAgentRequest
  }>('/agents', async (request, reply) => {
    const principal = await requirePrincipal(request, 'agents:write')
    const body = createAgentSchema.parse(request.body)
    const { agent, tokenBound } = await registerAgent(principal, body, request)

    const response: CreateAgentResponse = {
      agent: toAgentSummary(agent),
      token_bound: tokenBound,
    }
    return reply.code(201).header('Cache-Control', 'no-store').send(response)
  })

  fastify.get<{
    Querystring: { include_revoked?: string }
  }>('/agents', async (request, reply) => {
    const principal = await requirePrincipal(request, 'agents:read')
    const query = listAgentsQuerySchema.parse(request.query)
    const includeRevoked = query.include_revoked === '1' || query.include_revoked === 'true'
    const agents = await listAgents(principal.user.id, includeRevoked)

    const response: ListAgentsResponse = { agents: agents.map(toAgentSummary) }
    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.delete<{
    Params: { agentId: string }
  }>('/agents/:agentId', async (request, reply) => {
    const principal = await requirePrincipal(request, 'agents:write')
    const { agentId } = agentParamsSchema.parse(request.params)
    const result = await revokeAgent(principal, agentId, request)

    if (!result) {
      return reply.code(404).send({ error: 'Agent not found' })
    }

    const response: RevokeAgentResponse = {
      agent: toAgentSummary(result.agent),
      tokens_revoked: result.tokensRevoked,
    }
    return reply.header('Cache-Control', 'no-store').send(response)
  })
}
