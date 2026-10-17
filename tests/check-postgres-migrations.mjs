// Postgres migration checks. Each scenario uses its own fresh database and
// fails on any `prisma migrate diff` against prisma/schema.postgres.prisma:
//
// 1. fresh:   migrate deploy, diff, boot the server (startup DDL), diff again
// 2. up:      plain `pastevault up` on an empty database (migrations on by
//             default) applies every migration before serving
// 3. upgrade: a database at the PR1 schema (migrations up to
//             20261016_file_share_burn_and_upload_token, with a legacy
//             burn-after-read paste) is booted by the new server without
//             migrations, then migrated
//
//   E2E_POSTGRES_URL=postgres://postgres:pw@127.0.0.1:5432/postgres \
//     node tests/check-postgres-migrations.mjs
import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { cp, mkdir, mkdtemp, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { generatePrismaClient, nonce, projectRoot, reservePort, sleep } from './lib/harness.mjs'

const execFileAsync = promisify(execFile)
const adminUrl = process.env.E2E_POSTGRES_URL
const PR1_LAST_MIGRATION = '20261016_file_share_burn_and_upload_token'
const prismaBin = path.join(projectRoot, 'node_modules', '.bin', 'prisma')

if (!adminUrl) {
  console.error('Set E2E_POSTGRES_URL to a Postgres server where databases may be created')
  process.exit(2)
}

const { default: pg } = await import('pg')
const scratch = await mkdtemp(path.join(tmpdir(), 'pastevault-migrations-'))
const createdDatabases = []

async function adminQuery(sql) {
  const client = new pg.Client({ connectionString: adminUrl })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end()
  }
}

async function createDatabase(label) {
  const name = `pv_migrations_${label}_${randomBytes(4).toString('hex')}`
  await adminQuery(`CREATE DATABASE "${name}"`)
  createdDatabases.push(name)
  const url = new URL(adminUrl)
  url.pathname = `/${name}`
  const databaseUrl = url.toString()

  return {
    url: databaseUrl,
    environment: { ...process.env, DATABASE_PROVIDER: 'postgresql', DATABASE_URL: databaseUrl },
    async query(sql, ...params) {
      const client = new pg.Client({ connectionString: databaseUrl })
      await client.connect()
      try {
        return (await client.query(sql, params)).rows
      } finally {
        await client.end()
      }
    },
  }
}

// Runs the Prisma CLI with the repository's config. `packageRoot` swaps in a
// different prisma/ directory (schema and migrations).
function prisma(database, args, packageRoot) {
  return execFileAsync(prismaBin, [...args, `--config=${path.join(projectRoot, 'prisma.config.js')}`], {
    cwd: projectRoot,
    env: {
      ...database.environment,
      ...(packageRoot ? { PASTEVAULT_PACKAGE_ROOT: packageRoot } : {}),
    },
  })
}

async function assertNoDrift(database, stage) {
  const diffArgs = [
    'migrate',
    'diff',
    '--from-config-datasource',
    '--to-schema',
    path.join(projectRoot, 'prisma/schema.postgres.prisma'),
  ]

  try {
    await prisma(database, [...diffArgs, '--exit-code'])
  } catch {
    const { stdout } = await prisma(database, [...diffArgs, '--script']).catch((failure) => failure)
    throw new Error(`Schema drift ${stage}:\n${stdout}`)
  }
  console.log(`  no drift ${stage}`)
}

// Boots dist/cli.js against the database, runs `check` against it, stops it.
async function withServer(database, { migrations }, check) {
  const dataDirectory = path.join(scratch, `data-${randomBytes(4).toString('hex')}`)
  const port = await reservePort()
  const baseUrl = `http://127.0.0.1:${port}`
  const output = []
  const child = spawn(
    process.execPath,
    [
      'dist/cli.js',
      'up',
      '--port',
      String(port),
      '--host',
      '127.0.0.1',
      '--data-dir',
      dataDirectory,
      '--log-level',
      'info',
      ...(migrations ? [] : ['--no-migrations']),
    ],
    {
      cwd: projectRoot,
      env: { ...database.environment, NODE_ENV: 'test' },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  )
  child.stdout.on('data', (chunk) => output.push(chunk.toString()))
  child.stderr.on('data', (chunk) => output.push(chunk.toString()))

  try {
    const deadline = Date.now() + 60_000
    for (;;) {
      if (child.exitCode !== null) {
        throw new Error(`PasteVault exited early:\n${output.join('')}`)
      }
      const ready = await fetch(`${baseUrl}/health`)
        .then((response) => response.ok)
        .catch(() => false)
      if (ready) {
        break
      }
      if (Date.now() > deadline) {
        throw new Error(`PasteVault did not start:\n${output.join('')}`)
      }
      await sleep(200)
    }

    await check(baseUrl, output.join(''))
  } finally {
    child.kill('SIGTERM')
    if (child.exitCode === null) {
      await new Promise((resolve) => child.once('exit', resolve))
    }
  }
}

async function appliedMigrations(database) {
  return database.query(
    'SELECT "migration_name", "finished_at", "rolled_back_at" FROM "_prisma_migrations" ORDER BY "migration_name"'
  )
}

async function expectedMigrations() {
  return (await readdir(path.join(projectRoot, 'prisma/migrations'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
}

async function fresh() {
  console.log('fresh database: migrate deploy, then boot')
  const database = await createDatabase('fresh')
  await prisma(database, ['migrate', 'deploy'])
  await assertNoDrift(database, 'after migrate deploy')
  await withServer(database, { migrations: false }, async (baseUrl) => {
    assert.equal((await fetch(`${baseUrl}/api/capabilities`)).status, 200)
  })
  await assertNoDrift(database, 'after booting the server')
}

async function plainUp() {
  console.log('empty database: plain `pastevault up` runs the migrations')
  const database = await createDatabase('up')
  await withServer(database, { migrations: true }, async (baseUrl, output) => {
    assert.match(output, /Database migrations completed/)
    assert.doesNotMatch(output, /Migration failed/)
    assert.equal((await fetch(`${baseUrl}/api/capabilities`)).status, 200)
  })

  const applied = await appliedMigrations(database)
  assert.deepEqual(
    applied.map((row) => row.migration_name),
    await expectedMigrations()
  )
  for (const row of applied) {
    assert(row.finished_at && !row.rolled_back_at, `${row.migration_name} did not apply cleanly`)
  }
  console.log(`  ${applied.length} migrations applied by \`up\``)
  await assertNoDrift(database, 'after `up`')
}

async function upgradeFromPr1() {
  console.log('PR1 database: boot the new server first, then migrate')
  // A package root whose prisma/ directory only has the PR1-era migrations.
  const pr1Root = path.join(scratch, 'pr1-root')
  await mkdir(path.join(pr1Root, 'prisma/migrations'), { recursive: true })
  await cp(
    path.join(projectRoot, 'prisma/schema.postgres.prisma'),
    path.join(pr1Root, 'prisma/schema.postgres.prisma')
  )
  await cp(
    path.join(projectRoot, 'prisma/migrations/migration_lock.toml'),
    path.join(pr1Root, 'prisma/migrations/migration_lock.toml')
  )
  for (const name of await expectedMigrations()) {
    if (name <= PR1_LAST_MIGRATION) {
      await cp(
        path.join(projectRoot, 'prisma/migrations', name),
        path.join(pr1Root, 'prisma/migrations', name),
        { recursive: true }
      )
    }
  }

  const database = await createDatabase('upgrade')
  await prisma(database, ['migrate', 'deploy'], pr1Root)
  assert.equal((await appliedMigrations(database)).at(-1).migration_name, PR1_LAST_MIGRATION)
  await database.query(
    'INSERT INTO "Paste" ("id", "slug", "ciphertext", "nonce", "burn_after_read") VALUES ($1, $2, $3, $4, true)',
    'legacy-burn-paste',
    'legacy-burn-slug',
    Buffer.from('legacy ciphertext').toString('base64'),
    nonce
  )

  await withServer(database, { migrations: false }, async (baseUrl) => {
    const meta = await (await fetch(`${baseUrl}/api/pastes/legacy-burn-slug/meta`)).json()
    assert.equal(meta.max_views, 1)
    assert.equal(meta.views_remaining, 1)
    const read = await fetch(`${baseUrl}/api/pastes/legacy-burn-slug`)
    assert.equal(read.status, 200)
    assert.equal((await read.json()).metadata.is_burned, true)
    assert.equal((await fetch(`${baseUrl}/api/pastes/legacy-burn-slug`)).status, 410)
  })
  // The startup DDL alone already matches the schema exactly.
  await assertNoDrift(database, 'after booting on the PR1 schema')

  await prisma(database, ['migrate', 'deploy'])
  const applied = await appliedMigrations(database)
  assert.deepEqual(
    applied.map((row) => row.migration_name),
    await expectedMigrations()
  )
  assert(applied.every((row) => row.finished_at && !row.rolled_back_at))
  await assertNoDrift(database, 'after migrating')
}

try {
  await generatePrismaClient({
    ...process.env,
    DATABASE_PROVIDER: 'postgresql',
    DATABASE_URL: adminUrl,
  })
  await fresh()
  await plainUp()
  await upgradeFromPr1()
  console.log('Postgres migration checks passed')
} finally {
  for (const name of createdDatabases) {
    await adminQuery(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`).catch((error) =>
      console.error(`Failed to drop ${name}`, error)
    )
  }
  await rm(scratch, { recursive: true, force: true })
  await generatePrismaClient()
}
