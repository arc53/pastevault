import Fastify from 'fastify'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import { cleanupExpiredPastes } from './lib/cleanup.js'
import { config } from './lib/config.js'
import { accountRoute } from './routes/account.js'
import { authRoute } from './routes/auth.js'
import { fileSharesRoute } from './routes/file-shares.js'
import { pastesRoute } from './routes/pastes.js'
import * as cron from 'node-cron'

const fastify = Fastify({
  logger: {
    level: config.NODE_ENV === 'production' ? 'warn' : 'info',
  },
})

async function start() {
  try {
    await fastify.register(cors, {
      origin: config.NODE_ENV === 'production' ? config.CORS_ORIGIN : true,
      credentials: true,
      methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    })

    await fastify.register(rateLimit, {
      max: config.RATE_LIMIT_MAX,
      timeWindow: config.RATE_LIMIT_WINDOW_MS,
    })

    await fastify.register(authRoute, { prefix: '/api' })
    await fastify.register(accountRoute, { prefix: '/api' })
    await fastify.register(pastesRoute, { prefix: '/api' })
    await fastify.register(fileSharesRoute, { prefix: '/api' })

    fastify.get('/', async () => {
      return {
        service: 'PasteVault API',
        message:
          'Backend dev server is running. Start the frontend with `cd frontend && npm run dev` for the web UI.',
        frontend_dev_url: 'http://localhost:3002',
        endpoints: {
          health: '/health',
          api: '/api',
          capabilities: '/api/capabilities',
        },
      }
    })

    fastify.get('/health', async () => {
      return { status: 'ok', timestamp: new Date().toISOString() }
    })

    cron.schedule(`*/${config.CLEANUP_INTERVAL_MINUTES} * * * *`, () => {
      fastify.log.info('Running cleanup job')
      cleanupExpiredPastes().catch((error) => {
        fastify.log.error('Cleanup job failed:', error)
      })
    })

    await fastify.listen({ port: config.PORT, host: '0.0.0.0' })
    fastify.log.info(`Server listening on port ${config.PORT}`)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()
