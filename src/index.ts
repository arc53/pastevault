import Fastify from 'fastify'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import { config } from './lib/config'
import { pastesRoute } from './routes/pastes'
import { cleanupExpiredPastes } from './lib/cleanup'
import * as cron from 'node-cron'

const fastify = Fastify({
  logger: {
    level: config.NODE_ENV === 'production' ? 'warn' : 'info',
  },
})

async function start() {
  try {
    await fastify.register(cors, {
      origin: config.CORS_ORIGIN,
      credentials: true,
    })

    await fastify.register(rateLimit, {
      max: config.RATE_LIMIT_MAX,
      timeWindow: config.RATE_LIMIT_WINDOW_MS,
    })

    await fastify.register(pastesRoute, { prefix: '/api' })

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