import type { FastifyInstance } from 'fastify'
import { config } from '../lib/config.js'
import { getPrincipal, presentsApiToken } from '../lib/principal.js'
import { HttpError } from '../lib/validation.js'
import { fileSharesRoute } from './file-shares.js'
import { pastesRoute } from './pastes.js'

// All /api routes, shared by the dev server (src/index.ts) and the CLI
// (src/cli.ts) so the two can't drift. With DISABLE_AUTH the account, token,
// agent and audit routes are not registered at all (404).
export async function registerApiRoutes(fastify: FastifyInstance) {
  if (!config.DISABLE_AUTH) {
    // A request presenting an unknown, revoked or expired API token fails with
    // 401 on every API route, including ones that never look at the principal
    // (metadata, chunks, capabilities), so a broken token is always noticed.
    // The auth routes reject API tokens themselves.
    fastify.addHook('onRequest', async (request, reply) => {
      if (
        !request.url.startsWith('/api/') ||
        request.url.startsWith('/api/auth/') ||
        !presentsApiToken(request)
      ) {
        return
      }

      try {
        await getPrincipal(request)
      } catch (error: unknown) {
        if (error instanceof HttpError) {
          return reply.code(error.statusCode).send(error.body)
        }
        throw error
      }
    })

    const [{ authRoute }, { accountRoute }, { tokensRoute }, { agentsRoute }, { secretRequestsRoute }] =
      await Promise.all([
        import('./auth.js'),
        import('./account.js'),
        import('./tokens.js'),
        import('./agents.js'),
        import('./secret-requests.js'),
      ])
    await fastify.register(authRoute, { prefix: '/api' })
    await fastify.register(accountRoute, { prefix: '/api' })
    await fastify.register(tokensRoute, { prefix: '/api' })
    await fastify.register(agentsRoute, { prefix: '/api' })
    await fastify.register(secretRequestsRoute, { prefix: '/api' })
  }

  await fastify.register(pastesRoute, { prefix: '/api' })
  await fastify.register(fileSharesRoute, { prefix: '/api' })
}
