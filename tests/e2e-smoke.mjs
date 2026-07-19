import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'

const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'pastevault-e2e-'))
const databasePath = path.join(temporaryRoot, 'pastevault.db')
const dataDirectory = path.join(temporaryRoot, 'data')
const nonce = Buffer.alloc(24, 7).toString('base64url')
const serverOutput = []
const execFileAsync = promisify(execFile)

function reservePort() {
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

    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  throw new Error('Timed out waiting for PasteVault to start')
}

async function readResponse(response) {
  const text = await response.text()
  let body = text

  try {
    body = JSON.parse(text)
  } catch {
    // HTML and binary responses are asserted as their original text.
  }

  return { response, body }
}

async function request(baseUrl, pathname, options) {
  return readResponse(await fetch(`${baseUrl}${pathname}`, options))
}

async function stopServer(child) {
  if (child.exitCode !== null) {
    return
  }

  child.kill('SIGTERM')
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ])

  if (child.exitCode === null) {
    child.kill('SIGKILL')
  }
}

async function generatePrismaClient(environment = process.env) {
  await execFileAsync(
    process.execPath,
    ['scripts/prisma-runner.mjs', 'generate'],
    {
      cwd: projectRoot,
      env: environment,
    }
  )
}

let child
let shouldRestorePrisma = false

try {
  shouldRestorePrisma = true
  await generatePrismaClient({
    ...process.env,
    DATABASE_PROVIDER: 'sqlite',
    DATABASE_URL: `file:${databasePath}`,
  })

  const port = await reservePort()
  const baseUrl = `http://127.0.0.1:${port}`
  child = spawn(
    process.execPath,
    [
      'dist/cli.js',
      'up',
      '--port',
      String(port),
      '--host',
      '127.0.0.1',
      '--database-url',
      `file:${databasePath}`,
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
        DATABASE_PROVIDER: 'sqlite',
        NODE_ENV: 'test',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  )

  child.stdout.on('data', (chunk) => serverOutput.push(chunk.toString()))
  child.stderr.on('data', (chunk) => serverOutput.push(chunk.toString()))

  await waitForServer(baseUrl, child)

  const health = await request(baseUrl, '/health')
  assert.equal(health.response.status, 200)
  assert.equal(health.body.status, 'ok')
  assert.match(health.body.version, /^\d+\.\d+\.\d+$/)

  const home = await request(baseUrl, '/')
  assert.equal(home.response.status, 200)
  assert.match(home.response.headers.get('content-type') ?? '', /text\/html/)
  assert.match(home.body, /PasteVault/i)

  const capabilities = await request(baseUrl, '/api/capabilities')
  assert.equal(capabilities.response.status, 200)
  assert.equal(capabilities.body.file_shares.enabled, true)

  const pasteSlug = `e2e-paste-${randomUUID()}`
  const ciphertext = Buffer.from('opaque e2e ciphertext').toString('base64')
  const createPaste = await request(baseUrl, '/api/pastes', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: pasteSlug,
      ciphertext,
      nonce,
      burn_after_read: false,
      expires_in_hours: 1,
    }),
  })
  assert.equal(createPaste.response.status, 201)
  assert.equal(createPaste.body.slug, pasteSlug)

  const firstPasteView = await request(baseUrl, `/api/pastes/${pasteSlug}`)
  assert.equal(firstPasteView.response.status, 200)
  assert.equal(firstPasteView.body.ciphertext, ciphertext)
  assert.equal(firstPasteView.body.nonce, nonce)
  assert.equal(firstPasteView.body.metadata.view_count, 1)

  const secondPasteView = await request(baseUrl, `/api/pastes/${pasteSlug}`)
  assert.equal(secondPasteView.response.status, 200)
  assert.equal(secondPasteView.body.metadata.view_count, 2)

  const pastePage = await request(baseUrl, `/p/${pasteSlug}`)
  assert.equal(pastePage.response.status, 200)
  assert.match(pastePage.response.headers.get('content-type') ?? '', /text\/html/)

  const burnSlug = `e2e-burn-${randomUUID()}`
  const createBurnPaste = await request(baseUrl, '/api/pastes', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: burnSlug,
      ciphertext,
      nonce,
      burn_after_read: true,
    }),
  })
  assert.equal(createBurnPaste.response.status, 201)

  const burnRead = await request(baseUrl, `/api/pastes/${burnSlug}`)
  assert.equal(burnRead.response.status, 200)
  assert.equal(burnRead.body.metadata.is_burned, true)

  const burnedRead = await request(baseUrl, `/api/pastes/${burnSlug}`)
  assert.equal(burnedRead.response.status, 410)
  assert.equal(burnedRead.body.error, 'Paste has been burned')

  const fileSlug = `e2e-file-${randomUUID()}`
  const fileId = 'e2e_file_0001'
  const encryptedChunk = Buffer.from('encrypted file chunk')
  const createFileShare = await request(baseUrl, '/api/file-shares', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: fileSlug,
      file_count: 1,
      total_size_bytes: encryptedChunk.length,
      expires_in_hours: 1,
    }),
  })
  assert.equal(createFileShare.response.status, 201)
  assert.equal(createFileShare.body.slug, fileSlug)

  const uploadChunk = await request(
    baseUrl,
    `/api/file-shares/${fileSlug}/chunks/${fileId}/0`,
    {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: encryptedChunk,
    }
  )
  assert.equal(uploadChunk.response.status, 204)

  const manifestCiphertext = Buffer.from('opaque manifest').toString('base64')
  const completeFileShare = await request(
    baseUrl,
    `/api/file-shares/${fileSlug}/complete`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        manifest_ciphertext: manifestCiphertext,
        manifest_nonce: nonce,
      }),
    }
  )
  assert.equal(completeFileShare.response.status, 200)
  assert.equal(completeFileShare.body.slug, fileSlug)

  const getFileShare = await request(baseUrl, `/api/file-shares/${fileSlug}`)
  assert.equal(getFileShare.response.status, 200)
  assert.equal(getFileShare.body.manifest_ciphertext, manifestCiphertext)
  assert.equal(getFileShare.body.metadata.view_count, 1)

  const downloadedChunk = await fetch(
    `${baseUrl}/api/file-shares/${fileSlug}/chunks/${fileId}/0`
  )
  assert.equal(downloadedChunk.status, 200)
  assert.deepEqual(
    Buffer.from(await downloadedChunk.arrayBuffer()),
    encryptedChunk
  )

  const missingApiRoute = await request(baseUrl, '/api/e2e-missing')
  assert.equal(missingApiRoute.response.status, 404)
  assert.equal(missingApiRoute.body.error, 'Not Found')

  console.log('E2E smoke test passed: UI, pastes, burn-after-read, and file shares')
} catch (error) {
  if (serverOutput.length > 0) {
    console.error(serverOutput.join(''))
  }
  throw error
} finally {
  if (child) {
    await stopServer(child)
  }
  await rm(temporaryRoot, { recursive: true, force: true })
  if (shouldRestorePrisma) {
    await generatePrismaClient()
  }
}
