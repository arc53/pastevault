import { FastifyInstance } from 'fastify'
import { ensureAccountSystemSchema } from '../lib/account-schema.js'
import {
  countActiveApiTokens,
  createApiToken,
  DEFAULT_TOKEN_SCOPES,
  getApiTokenForUser,
  listApiTokens,
  parseScopes,
  revokeApiToken,
} from '../lib/api-tokens.js'
import { auditActorFor, recordAuditEvent } from '../lib/audit.js'
import { getPrisma } from '../lib/db.js'
import { requirePrincipal, requireSession } from '../lib/principal.js'
import {
  apiTokenParamsSchema,
  createApiTokenSchema,
  validationErrorHandler,
} from '../lib/validation.js'
import {
  ApiTokenSummary,
  CreateApiTokenRequest,
  CreateApiTokenResponse,
  ListApiTokensResponse,
  MeResponse,
} from '../types/index.js'

// Generous, but stops a leaked session from minting tokens without bound.
const MAX_ACTIVE_TOKENS_PER_USER = 100

type ApiTokenRow = Awaited<ReturnType<typeof listApiTokens>>[number]

async function loadAgents(ids: Array<string | null>) {
  const agentIds = [...new Set(ids.filter((id): id is string => Boolean(id)))]
  if (agentIds.length === 0) {
    return new Map<string, { id: string; name: string; fingerprint: string }>()
  }

  const agents = await getPrisma().agentIdentity.findMany({
    where: { id: { in: agentIds } },
    select: { id: true, name: true, fingerprint: true },
  })
  return new Map(agents.map((agent) => [agent.id, agent]))
}

function toApiTokenSummary(
  token: ApiTokenRow,
  agents: Map<string, { id: string; name: string }>
): ApiTokenSummary {
  const agent = token.agent_id ? agents.get(token.agent_id) : undefined

  return {
    id: token.id,
    name: token.name,
    prefix: token.token_prefix,
    scopes: parseScopes(token.scopes),
    agent: agent ? { id: agent.id, name: agent.name } : null,
    created_at: token.created_at,
    expires_at: token.expires_at,
    last_used_at: token.last_used_at,
    revoked_at: token.revoked_at,
  }
}

export async function tokensRoute(fastify: FastifyInstance) {
  await ensureAccountSystemSchema()

  fastify.setErrorHandler(validationErrorHandler)

  fastify.get('/me', async (request, reply) => {
    const principal = await requirePrincipal(request)
    const agent = principal.agent_id
      ? (await loadAgents([principal.agent_id])).get(principal.agent_id)
      : undefined

    const response: MeResponse = {
      user: {
        id: principal.user.id,
        username: principal.user.username,
        name: principal.user.name,
      },
      auth: {
        kind: principal.kind,
        ...(principal.token_id ? { token_id: principal.token_id } : {}),
        scopes: [...principal.scopes],
        ...(agent ? { agent } : {}),
      },
    }

    return reply.header('Cache-Control', 'no-store').send(response)
  })

  // Token management is session-only: a token can never mint, list or revoke
  // tokens, so a leaked token can't extend its own reach or lifetime.
  fastify.post<{
    Body: CreateApiTokenRequest
  }>('/account/tokens', async (request, reply) => {
    const principal = await requireSession(request)
    const body = createApiTokenSchema.parse(request.body)

    if (body.agent_id) {
      const agent = await getPrisma().agentIdentity.findFirst({
        where: { id: body.agent_id, user_id: principal.user.id, revoked_at: null },
        select: { id: true },
      })
      if (!agent) {
        return reply.code(400).send({ error: 'Unknown agent' })
      }
    }

    if ((await countActiveApiTokens(principal.user.id)) >= MAX_ACTIVE_TOKENS_PER_USER) {
      return reply.code(409).send({
        error: `An account can have at most ${MAX_ACTIVE_TOKENS_PER_USER} active tokens; revoke some first`,
      })
    }

    const { record, token } = await createApiToken({
      user_id: principal.user.id,
      name: body.name,
      scopes: body.scopes ?? DEFAULT_TOKEN_SCOPES,
      expires_at:
        body.expires_in_days === null
          ? null
          : new Date(Date.now() + body.expires_in_days * 24 * 60 * 60 * 1000),
      agent_id: body.agent_id ?? null,
    })

    await recordAuditEvent({
      user_id: principal.user.id,
      subject_type: 'token',
      subject_id: record.id,
      event: 'token.created',
      actor: auditActorFor(principal, principal.user.id),
      details: {
        name: record.name,
        prefix: record.token_prefix,
        scopes: parseScopes(record.scopes),
        expires_at: record.expires_at,
      },
      request,
    })

    const response: CreateApiTokenResponse = {
      id: record.id,
      token,
      name: record.name,
      prefix: record.token_prefix,
      scopes: parseScopes(record.scopes),
      agent_id: record.agent_id,
      expires_at: record.expires_at,
    }

    return reply.code(201).header('Cache-Control', 'no-store').send(response)
  })

  fastify.get('/account/tokens', async (request, reply) => {
    const principal = await requireSession(request)
    const tokens = await listApiTokens(principal.user.id)
    const agents = await loadAgents(tokens.map((token) => token.agent_id))

    const response: ListApiTokensResponse = {
      tokens: tokens.map((token) => toApiTokenSummary(token, agents)),
    }

    return reply.header('Cache-Control', 'no-store').send(response)
  })

  fastify.delete<{
    Params: { tokenId: string }
  }>('/account/tokens/:tokenId', async (request, reply) => {
    const principal = await requireSession(request)
    const { tokenId } = apiTokenParamsSchema.parse(request.params)
    const existing = await getApiTokenForUser(tokenId, principal.user.id)

    if (!existing) {
      return reply.code(404).send({ error: 'Token not found' })
    }

    // Revoking twice keeps the original revocation time.
    const token = existing.revoked_at ? existing : await revokeApiToken(existing.id)

    if (!existing.revoked_at) {
      await recordAuditEvent({
        user_id: principal.user.id,
        subject_type: 'token',
        subject_id: token.id,
        event: 'token.revoked',
        actor: auditActorFor(principal, principal.user.id),
        details: { name: token.name, prefix: token.token_prefix },
        request,
      })
    }

    const agents = await loadAgents([token.agent_id])
    return reply.send({ token: toApiTokenSummary(token, agents) })
  })
}
