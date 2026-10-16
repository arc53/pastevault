import type { FastifyInstance } from 'fastify'
import { config } from '../lib/config.js'
import { fileSharesRoute } from './file-shares.js'
import { pastesRoute } from './pastes.js'

// All /api routes, shared by the dev server (src/index.ts) and the CLI
// (src/cli.ts) so the two can't drift. With DISABLE_AUTH the account, token
// and audit routes are not registered at all (404).
export async function registerApiRoutes(fastify: FastifyInstance) {
  if (!config.DISABLE_AUTH) {
    const [{ authRoute }, { accountRoute }, { tokensRoute }] = await Promise.all([
      import('./auth.js'),
      import('./account.js'),
      import('./tokens.js'),
    ])
    await fastify.register(authRoute, { prefix: '/api' })
    await fastify.register(accountRoute, { prefix: '/api' })
    await fastify.register(tokensRoute, { prefix: '/api' })
  }

  await fastify.register(pastesRoute, { prefix: '/api' })
  await fastify.register(fileSharesRoute, { prefix: '/api' })
}
