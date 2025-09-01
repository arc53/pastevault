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

    // Serve frontend redirect in CLI mode (simpler approach for now)
    const isCliMode = process.env.PASTEVAULT_CLI_MODE === 'true'
    if (isCliMode) {
      // Simple redirect to frontend server for now
      fastify.get('/*', async (request, reply) => {
        // Skip API routes and health
        if (request.url.startsWith('/api/') || request.url.startsWith('/health')) {
          return reply.callNotFound()
        }
        
        const frontendPort = parseInt(config.PORT.toString()) + 1
        const frontendUrl = `http://localhost:${frontendPort}`
        
        const redirectHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PasteVault</title>
  <script>
    // Redirect to the frontend server
    window.location.href = '${frontendUrl}' + window.location.pathname + window.location.search + window.location.hash;
  </script>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f9fafb;
    }
    .loading {
      text-align: center;
    }
    .spinner {
      border: 3px solid #f3f4f6;
      border-top: 3px solid #3b82f6;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="loading">
    <div class="spinner"></div>
    <p>Loading PasteVault...</p>
    <p><a href="${frontendUrl}">Click here if not redirected automatically</a></p>
  </div>
</body>
</html>`
        reply.type('text/html').send(redirectHtml)
      })
    }

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
