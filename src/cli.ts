#!/usr/bin/env node

import { Command } from 'commander'
import { exec as execCallback } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import * as cron from 'node-cron'
import { z } from 'zod'

const execAsync = promisify(execCallback)
const packageRoot = fileURLToPath(new URL('..', import.meta.url))
const frontendDir = fileURLToPath(new URL('../frontend', import.meta.url))
const packageInfo = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
) as { version: string }

const cliArgsSchema = z.object({
  port: z.number().default(3001),
  host: z.string().default('localhost'),
  databaseUrl: z.string().optional(),
  dataDir: z.string().optional(),
  logLevel: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
  noMigrations: z.boolean().default(false),
})

type CliArgs = z.infer<typeof cliArgsSchema>

const program = new Command()

program
  .name('pastevault')
  .description('PasteVault - Secure end-to-end encrypted paste sharing')
  .version(packageInfo.version)

program
  .command('up')
  .description('Start PasteVault server')
  .option('-p, --port <number>', 'Port to listen on', '3001')
  .option('-h, --host <string>', 'Host to bind to', 'localhost')
  .option('--database-url <string>', 'Database connection URL')
  .option('--data-dir <string>', 'Data directory path')
  .option('--log-level <level>', 'Log level', 'info')
  .option('--no-migrations', 'Skip running database migrations', false)
  .action(async (options) => {
    const args = cliArgsSchema.parse({
      port: parseInt(options.port),
      host: options.host,
      databaseUrl: options.databaseUrl,
      dataDir: options.dataDir,
      logLevel: options.logLevel,
      noMigrations: options.noMigrations,
    })

    await startServer(args)
  })

program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`pastevault CLI: ${packageInfo.version}`)
    console.log(`pastevault App: ${packageInfo.version}`)
  })

async function startServer(args: CliArgs) {
  try {
    const resolvedHost = args.host === '0.0.0.0' ? 'localhost' : args.host

    // Set environment variables from CLI args
    if (args.databaseUrl) {
      process.env.DATABASE_URL = args.databaseUrl
    }

    if (args.dataDir) {
      process.env.DATA_DIR = args.dataDir
    }

    process.env.PORT = args.port.toString()
    process.env.CORS_ORIGIN = process.env.CORS_ORIGIN || `http://${resolvedHost}:${args.port}`
    process.env.BETTER_AUTH_URL =
      process.env.BETTER_AUTH_URL || `http://${resolvedHost}:${args.port}/api/auth`

    const [
      { config },
      { authRoute },
      { accountRoute },
      { pastesRoute },
      { fileSharesRoute },
      { cleanupExpiredPastes },
    ] = await Promise.all([
      import('./lib/config.js'),
      import('./routes/auth.js'),
      import('./routes/account.js'),
      import('./routes/pastes.js'),
      import('./routes/file-shares.js'),
      import('./lib/cleanup.js'),
    ])

    if (!process.env.DATABASE_URL) {
      process.env.DATABASE_URL = config.DATABASE_URL
    }

    process.env.DATABASE_PROVIDER = process.env.DATABASE_PROVIDER || config.DATABASE_PROVIDER

    const fastify = Fastify({
      logger: {
        level: args.logLevel,
      },
    })

    // Register CORS with unrestricted access for CLI
    await fastify.register(cors, {
      origin: true,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'Referer'],
      exposedHeaders: ['*'],
      preflightContinue: false,
      optionsSuccessStatus: 200,
    })

    // Register rate limiting
    await fastify.register(rateLimit, {
      max: config.RATE_LIMIT_MAX,
      timeWindow: config.RATE_LIMIT_WINDOW_MS,
    })

    // Register API routes
    await fastify.register(authRoute, { prefix: '/api' })
    await fastify.register(accountRoute, { prefix: '/api' })
    await fastify.register(pastesRoute, { prefix: '/api' })
    await fastify.register(fileSharesRoute, { prefix: '/api' })

    // Health check endpoint
    fastify.get('/health', async () => {
      return { 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        version: packageInfo.version
      }
    })

    // Setup Next.js
    const nextModule = await import('next')
    const createNext = nextModule.default as unknown as (options: {
      dev: boolean
      dir: string
      quiet?: boolean
    }) => {
      getRequestHandler: () => (req: unknown, res: unknown) => Promise<void>
      prepare: () => Promise<void>
    }
    fastify.log.info(`Looking for Next.js build in: ${frontendDir}`)
    
    const nextApp = createNext({ 
      dev: false, 
      dir: frontendDir,
      quiet: args.logLevel !== 'debug' && args.logLevel !== 'trace'
    })
    const handle = nextApp.getRequestHandler()

    await nextApp.prepare()

    // Handle all non-API routes with Next.js
    fastify.setNotFoundHandler(async (request, reply) => {
      const { url } = request
      
      // Skip API routes - let Fastify handle 404s for API routes
      if (url?.startsWith('/api/')) {
        reply.code(404).send({ error: 'Not Found' })
        return
      }

      // Handle with Next.js for all other routes
      return handle(request.raw, reply.raw).then(() => {
        reply.sent = true
      })
    })

    // Run database migrations if not disabled
    if (!args.noMigrations) {
      try {
        fastify.log.info('Running database migrations...')
        await execAsync('node scripts/prisma-runner.mjs migrate deploy', {
          cwd: packageRoot,
        })
        fastify.log.info('Database migrations completed')
      } catch (error) {
        fastify.log.warn('Migration failed, continuing anyway:')
        fastify.log.warn(error)
      }
    }

    // Setup cleanup cron job
    cron.schedule(`*/${config.CLEANUP_INTERVAL_MINUTES} * * * *`, () => {
      fastify.log.info('Running cleanup job')
      cleanupExpiredPastes().catch((error) => {
        fastify.log.error('Cleanup job failed:', error)
      })
    })

    // Start server
    await fastify.listen({ port: args.port, host: args.host })
    
    console.log(`🚀 PasteVault is running!`)
    console.log(`📱 Web UI: http://localhost:${args.port}`)
    console.log(`🔗 API: http://localhost:${args.port}/api`)
    console.log(`💚 Health: http://localhost:${args.port}/health`)
    console.log(`📊 Version: ${packageInfo.version}`)
    console.log(`\n✨ Ready to accept pastes!`)

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      fastify.log.info(`Received ${signal}, shutting down gracefully...`)
      try {
        await fastify.close()
        process.exit(0)
      } catch (error) {
        fastify.log.error('Error during shutdown:')
        fastify.log.error(error)
        process.exit(1)
      }
    }

    process.on('SIGINT', () => shutdown('SIGINT'))
    process.on('SIGTERM', () => shutdown('SIGTERM'))

  } catch (error) {
    console.error('Failed to start server:', error)
    process.exit(1)
  }
}

// Run the CLI if this file is executed directly
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  program.parse()
}

export { program }
