// Checks that the Postgres migrations produce exactly prisma/schema.postgres.prisma:
// deploys every migration into a fresh database, then fails if
// `prisma migrate diff` finds any difference.
//
//   E2E_POSTGRES_URL=postgres://postgres:pw@127.0.0.1:5432/postgres \
//     node tests/check-postgres-migrations.mjs
//
// With --boot, a PasteVault server (dist/) is also started on the migrated
// database before diffing again, so the startup DDL is checked too.
import { execFile, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { generatePrismaClient, projectRoot, reservePort, sleep } from './lib/harness.mjs'

const execFileAsync = promisify(execFile)
const adminUrl = process.env.E2E_POSTGRES_URL
const boot = process.argv.includes('--boot')

if (!adminUrl) {
  console.error('Set E2E_POSTGRES_URL to a Postgres server where databases may be created')
  process.exit(2)
}

const { default: pg } = await import('pg')
const databaseName = `pv_migrations_${randomBytes(4).toString('hex')}`
const databaseUrl = Object.assign(new URL(adminUrl), { pathname: `/${databaseName}` }).toString()
const environment = { ...process.env, DATABASE_PROVIDER: 'postgresql', DATABASE_URL: databaseUrl }

async function adminQuery(sql) {
  const client = new pg.Client({ connectionString: adminUrl })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }
}

async function prisma(...args) {
  return execFileAsync(process.execPath, ['scripts/prisma-runner.mjs', ...args], {
    cwd: projectRoot,
    env: environment,
  })
}

async function assertNoDrift(stage) {
  try {
    await prisma(
      'migrate',
      'diff',
      '--from-config-datasource',
      '--to-schema',
      'prisma/schema.postgres.prisma',
      '--exit-code'
    )
    console.log(`No drift ${stage}`)
  } catch (error) {
    const { stdout } = await prisma(
      'migrate',
      'diff',
      '--from-config-datasource',
      '--to-schema',
      'prisma/schema.postgres.prisma',
      '--script'
    ).catch((failure) => failure)
    console.error(`Schema drift ${stage}:\n${stdout ?? error}`)
    process.exitCode = 1
  }
}

async function bootServer() {
  const dataDirectory = await mkdtemp(path.join(tmpdir(), 'pastevault-migrations-'))
  const port = await reservePort()
  await generatePrismaClient(environment)
  const child = spawn(
    process.execPath,
    ['dist/cli.js', 'up', '--port', String(port), '--host', '127.0.0.1', '--data-dir', dataDirectory, '--log-level', 'warn', '--no-migrations'],
    { cwd: projectRoot, env: { ...environment, NODE_ENV: 'test' }, stdio: 'ignore' }
  )

  try {
    const deadline = Date.now() + 30_000
    while (Date.now() < deadline) {
      const ready = await fetch(`http://127.0.0.1:${port}/api/capabilities`)
        .then((response) => response.ok)
        .catch(() => false)
      if (ready) {
        return
      }
      await sleep(200)
    }
    throw new Error('PasteVault did not start')
  } finally {
    child.kill('SIGTERM')
    await new Promise((resolve) => child.once('exit', resolve))
    await rm(dataDirectory, { recursive: true, force: true })
    await generatePrismaClient()
  }
}

await adminQuery(`CREATE DATABASE "${databaseName}"`)
try {
  await prisma('migrate', 'deploy')
  await assertNoDrift('after migrate deploy')

  if (boot) {
    await bootServer()
    await assertNoDrift('after booting the server')
  }
} finally {
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`)
}
