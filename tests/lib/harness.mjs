// Shared helpers for the end-to-end suites (tests/e2e-*.mjs). Each suite runs
// real `pastevault up` servers from dist/ against throwaway databases.
//
// Suites that pass `postgres: true` to runSuite run against Postgres when
// E2E_POSTGRES_URL points at a server where the test user may create
// databases (e.g. postgres://postgres:pw@127.0.0.1:5432/postgres). Every
// server then gets its own fresh, migrated database.
import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

export const projectRoot = fileURLToPath(new URL('../..', import.meta.url))
export const nonce = Buffer.alloc(24, 7).toString('base64url')

const execFileAsync = promisify(execFile)

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function reservePort() {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.unref()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      assert(address && typeof address === 'object')
      const { port } = address
      server.close((error) => (error ? reject(error) : resolve(port)))
    })
  })
}

export async function readResponse(response) {
  const text = await response.text()
  let body = text

  try {
    body = JSON.parse(text)
  } catch {
    // HTML and binary responses are asserted as their original text.
  }

  return { response, body }
}

export async function request(baseUrl, pathname, options) {
  return readResponse(await fetch(`${baseUrl}${pathname}`, options))
}

export function jsonRequest(baseUrl, pathname, body, headers = {}) {
  return request(baseUrl, pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

export function uploadChunk(baseUrl, slug, fileId, index, body, uploadToken) {
  return request(baseUrl, `/api/file-shares/${slug}/chunks/${fileId}/${index}`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      ...(uploadToken ? { 'x-upload-token': uploadToken } : {}),
    },
    body,
  })
}

export function readDatabaseRow(databasePath, sql, ...params) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return database.prepare(sql).get(...params)
  } finally {
    database.close()
  }
}

// SQLite returns booleans as 0/1, Postgres as true/false.
export function asBoolean(value) {
  return typeof value === 'boolean' ? value : Number(value) === 1
}

export async function generatePrismaClient(environment = process.env) {
  await execFileAsync(process.execPath, ['scripts/prisma-runner.mjs', 'generate'], {
    cwd: projectRoot,
    env: environment,
  })
}

async function waitForServer(baseUrl, child) {
  const deadline = Date.now() + 30_000

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`PasteVault exited before becoming ready (code ${child.exitCode})`)
    }

    try {
      const response = await fetch(`${baseUrl}/health`)
      if (response.ok) {
        return
      }
    } catch {
      // The listener may not be ready yet.
    }

    await sleep(100)
  }

  throw new Error('Timed out waiting for PasteVault to start')
}

async function stopChild(child) {
  if (child.exitCode !== null) {
    return
  }

  child.kill('SIGTERM')
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(5_000),
  ])

  if (child.exitCode === null) {
    child.kill('SIGKILL')
  }
}

function sqliteDatabase(databasePath) {
  return {
    provider: 'sqlite',
    path: databasePath,
    url: `file:${databasePath}`,
    // Statements use $1, $2 ... placeholders on both engines.
    async query(sql, ...params) {
      // The server holds the same file open; wait out its write locks.
      const database = new DatabaseSync(databasePath, { timeout: 5_000 })
      try {
        const statement = database.prepare(sql.replace(/\$(\d+)/g, '?$1'))
        return /^\s*select/i.test(sql) ? statement.all(...params) : [statement.run(...params)]
      } finally {
        database.close()
      }
    },
    async close() {},
  }
}

async function postgresDatabase(adminUrl, name) {
  const { default: pg } = await import('pg')
  const databaseName = `pv_e2e_${name.replace(/[^a-z0-9_]/gi, '_')}_${randomBytes(4).toString('hex')}`
  const admin = new pg.Client({ connectionString: adminUrl })
  await admin.connect()
  await admin.query(`CREATE DATABASE "${databaseName}"`)
  await admin.end()

  const url = new URL(adminUrl)
  url.pathname = `/${databaseName}`
  const databaseUrl = url.toString()

  await execFileAsync(process.execPath, ['scripts/prisma-runner.mjs', 'migrate', 'deploy'], {
    cwd: projectRoot,
    env: { ...process.env, DATABASE_PROVIDER: 'postgresql', DATABASE_URL: databaseUrl },
  })

  const client = new pg.Client({ connectionString: databaseUrl })
  await client.connect()

  return {
    provider: 'postgresql',
    url: databaseUrl,
    async query(sql, ...params) {
      return (await client.query(sql, params)).rows
    },
    async close() {
      await client.end()
      const dropper = new pg.Client({ connectionString: adminUrl })
      await dropper.connect()
      await dropper.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`)
      await dropper.end()
    },
  }
}

// Runs one suite: builds a scratch directory, generates the Prisma client for
// the engine under test, and always stops servers, drops databases and
// restores the default (SQLite) Prisma client afterwards. Server output is
// printed only when the suite fails.
export async function runSuite(name, { postgres = false } = {}, body) {
  const postgresUrl = postgres ? process.env.E2E_POSTGRES_URL : undefined
  const provider = postgresUrl ? 'postgresql' : 'sqlite'
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), `pastevault-${name}-`))
  const serverOutput = []
  const servers = new Set()
  const databases = []
  let shouldRestorePrisma = false

  const context = {
    provider,
    temporaryRoot,

    // A fresh database for one server. On SQLite a pre-existing file can be
    // passed to boot the server on an older schema.
    async createDatabase(label, { sqlitePath } = {}) {
      const database = postgresUrl
        ? await postgresDatabase(postgresUrl, label)
        : sqliteDatabase(sqlitePath ?? path.join(temporaryRoot, `${label}.db`))
      databases.push(database)
      return database
    },

    async startServer({ label = 'server', database, environment = {} } = {}) {
      const db = database ?? (await context.createDatabase(label))
      const port = await reservePort()
      const baseUrl = `http://127.0.0.1:${port}`
      const dataDirectory = path.join(temporaryRoot, `${label}-data`)
      const child = spawn(
        process.execPath,
        [
          'dist/cli.js',
          'up',
          '--port',
          String(port),
          '--host',
          '127.0.0.1',
          '--database-url',
          db.url,
          '--data-dir',
          dataDirectory,
          '--log-level',
          'warn',
          '--no-migrations',
        ],
        {
          cwd: projectRoot,
          env: {
            ...process.env,
            DATABASE_PROVIDER: db.provider,
            NODE_ENV: 'test',
            DISABLE_AUTH: 'false',
            DISABLE_SIGNUP: 'false',
            ...environment,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      )

      child.stdout.on('data', (chunk) => serverOutput.push(chunk.toString()))
      child.stderr.on('data', (chunk) => serverOutput.push(chunk.toString()))

      const server = {
        baseUrl,
        database: db,
        dataDirectory,
        child,
        async stop() {
          servers.delete(server)
          await stopChild(child)
        },
      }
      servers.add(server)
      await waitForServer(baseUrl, child)
      return server
    },
  }

  try {
    shouldRestorePrisma = true
    await generatePrismaClient({
      ...process.env,
      DATABASE_PROVIDER: provider,
      DATABASE_URL: postgresUrl ?? `file:${path.join(temporaryRoot, 'generate.db')}`,
    })

    await body(context)
  } catch (error) {
    if (serverOutput.length > 0) {
      console.error(serverOutput.join(''))
    }
    throw error
  } finally {
    for (const server of [...servers]) {
      await server.stop()
    }
    for (const database of databases) {
      await database.close().catch((error) => console.error('Failed to drop test database', error))
    }
    await rm(temporaryRoot, { recursive: true, force: true })
    if (shouldRestorePrisma) {
      await generatePrismaClient()
    }
  }
}

// Signs up a fresh account and returns its bearer session headers.
export async function signUp(baseUrl, label = 'owner') {
  const id = randomBytes(6).toString('hex')
  const signUpResponse = await jsonRequest(
    baseUrl,
    '/api/auth/sign-up/email',
    {
      name: `E2E ${label}`,
      email: `${label}-${id}@example.com`,
      username: `${label}_${id}`.slice(0, 30),
      password: 'correct-horse-battery-staple',
    },
    { origin: baseUrl }
  )
  assert.equal(signUpResponse.response.status, 200)
  const sessionToken =
    signUpResponse.response.headers.get('set-auth-token') || signUpResponse.body.token
  assert(sessionToken)

  return {
    user: signUpResponse.body.user,
    sessionToken,
    headers: { authorization: `Bearer ${sessionToken}` },
  }
}
