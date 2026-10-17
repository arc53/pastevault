#!/usr/bin/env node

import { Command } from 'commander'
import { exec as execCallback } from 'node:child_process'
import { readFileSync, realpathSync } from 'node:fs'
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
  // No explicit default: commander then sets `migrations` to true unless the
  // flag is given (an explicit `false` default would disable migrations).
  .option('--no-migrations', 'Skip running database migrations')
  .action(async (options) => {
    const args = cliArgsSchema.parse({
      port: parseInt(options.port),
      host: options.host,
      databaseUrl: options.databaseUrl,
      dataDir: options.dataDir,
      logLevel: options.logLevel,
      noMigrations: options.migrations === false,
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
      { registerApiRoutes },
      { cleanupExpiredPastes },
      { corsOptionsDelegator },
    ] = await Promise.all([
      import('./lib/config.js'),
      import('./routes/register.js'),
      import('./lib/cleanup.js'),
      import('./lib/origins.js'),
    ])

    if (!process.env.DATABASE_URL) {
      process.env.DATABASE_URL = config.DATABASE_URL
    }

    process.env.DATABASE_PROVIDER = process.env.DATABASE_PROVIDER || config.DATABASE_PROVIDER

    const fastify = Fastify({
      trustProxy: config.TRUST_PROXY,
      logger: {
        level: args.logLevel,
      },
    })

    // Migrations run before any route loads: routes create missing tables and
    // columns at startup, and a fresh Postgres database must get them from
    // the migrations instead. The migrations are Postgres-only; SQLite's
    // schema is maintained entirely at startup.
    if (args.noMigrations) {
      fastify.log.info('Skipping database migrations (--no-migrations)')
    } else if (process.env.DATABASE_PROVIDER !== 'postgresql') {
      fastify.log.info('SQLite schema is managed at startup; no migrations to run')
    } else {
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

    // CORS only for the server's own origin and configured trusted origins.
    await fastify.register(cors, { delegator: corsOptionsDelegator })

    // Register rate limiting
    await fastify.register(rateLimit, {
      max: config.RATE_LIMIT_MAX,
      timeWindow: config.RATE_LIMIT_WINDOW_MS,
    })

    // Register API routes
    await registerApiRoutes(fastify)

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

      // Handle with Next.js for all other routes. Next writes the raw
      // response itself, so Fastify must not send one.
      reply.hijack()
      await handle(request.raw, reply.raw)
    })

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

// Run the CLI if this file is executed directly. npx and global installs
// start it through a node_modules/.bin symlink, so compare real paths.
function isEntryPoint(): boolean {
  if (!process.argv[1]) return false
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])
  } catch {
    return false
  }
}

if (isEntryPoint()) {
  program.parse()
}

export { program }
