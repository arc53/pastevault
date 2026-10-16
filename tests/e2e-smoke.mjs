import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'
import { DatabaseSync } from 'node:sqlite'

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

function startTestServer({ port, databasePath, dataDirectory, environment = {} }) {
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
        DISABLE_AUTH: 'false',
        DISABLE_SIGNUP: 'false',
        ...environment,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  )

  child.stdout.on('data', (chunk) => serverOutput.push(chunk.toString()))
  child.stderr.on('data', (chunk) => serverOutput.push(chunk.toString()))

  return child
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

function jsonRequest(baseUrl, pathname, body, headers = {}) {
  return request(baseUrl, pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

function uploadChunk(baseUrl, slug, fileId, index, body, uploadToken) {
  return request(baseUrl, `/api/file-shares/${slug}/chunks/${fileId}/${index}`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      ...(uploadToken ? { 'x-upload-token': uploadToken } : {}),
    },
    body,
  })
}

function readDatabaseRow(databasePath, sql, ...params) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  try {
    return database.prepare(sql).get(...params)
  } finally {
    database.close()
  }
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
  child = startTestServer({ port, databasePath, dataDirectory })

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
  assert.equal(capabilities.body.auth.enabled, true)
  assert.equal(capabilities.body.auth.signup_enabled, true)
  assert.equal(capabilities.body.file_shares.enabled, true)
  assert.equal(capabilities.body.file_shares.burn_after_read, true)

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

  const duplicatePaste = await jsonRequest(baseUrl, '/api/pastes', {
    slug: pasteSlug,
    ciphertext,
    nonce,
  })
  assert.equal(duplicatePaste.response.status, 409)
  assert.match(duplicatePaste.body.error, /already exists/)

  for (const badSlug of ['abc', 'has space!', '../etc/passwd', 'x'.repeat(65)]) {
    const badSlugPaste = await jsonRequest(baseUrl, '/api/pastes', {
      slug: badSlug,
      ciphertext,
      nonce,
    })
    assert.equal(badSlugPaste.response.status, 400, `slug ${badSlug} should be rejected`)
    assert.match(badSlugPaste.body.error, /slug/)
  }

  const nanoidStyleSlug = await jsonRequest(baseUrl, '/api/pastes', {
    slug: 'V1StGXR8_Z5j',
    ciphertext,
    nonce,
  })
  assert.equal(nanoidStyleSlug.response.status, 201)

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

  // The metadata endpoint (used by link previews and the reveal screen) must not burn.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const burnMeta = await request(baseUrl, `/api/pastes/${burnSlug}/meta`)
    assert.equal(burnMeta.response.status, 200)
    assert.equal(burnMeta.body.burn_after_read, true)
    assert.equal(burnMeta.body.password_protected, false)
    assert.equal(burnMeta.body.is_burned, false)
    assert.equal(burnMeta.body.ciphertext, undefined)
  }

  // Link scanners send HEAD; it must neither burn nor return content.
  const headPaste = await fetch(`${baseUrl}/api/pastes/${burnSlug}`, { method: 'HEAD' })
  assert.equal(headPaste.status, 405)
  const headPasteMeta = await fetch(`${baseUrl}/api/pastes/${burnSlug}/meta`, { method: 'HEAD' })
  assert.equal(headPasteMeta.status, 200)
  assert.equal((await request(baseUrl, `/api/pastes/${burnSlug}/meta`)).response.status, 200)

  const burnRead = await request(baseUrl, `/api/pastes/${burnSlug}`)
  assert.equal(burnRead.response.status, 200)
  assert.equal(burnRead.body.ciphertext, ciphertext)
  assert.equal(burnRead.body.metadata.is_burned, true)

  const burnedRead = await request(baseUrl, `/api/pastes/${burnSlug}`)
  assert.equal(burnedRead.response.status, 410)
  assert.equal(burnedRead.body.error, 'Paste has been burned')

  const burnedMeta = await request(baseUrl, `/api/pastes/${burnSlug}/meta`)
  assert.equal(burnedMeta.response.status, 410)

  const missingMeta = await request(baseUrl, '/api/pastes/does-not-exist/meta')
  assert.equal(missingMeta.response.status, 404)

  const racedSlug = `e2e-race-${randomUUID()}`
  const createRacedPaste = await jsonRequest(baseUrl, '/api/pastes', {
    slug: racedSlug,
    ciphertext,
    nonce,
    salt: 'c2FsdHNhbHRzYWx0c2FsdA',
    kdf_params: '{"iterations":600000}',
    burn_after_read: true,
  })
  assert.equal(createRacedPaste.response.status, 201)

  const racedReads = await Promise.all(
    Array.from({ length: 10 }, () => request(baseUrl, `/api/pastes/${racedSlug}`))
  )
  const racedWinners = racedReads.filter(({ response }) => response.status === 200)
  const racedLosers = racedReads.filter(({ response }) => response.status === 410)
  assert.equal(racedWinners.length, 1, 'exactly one concurrent reader may burn a paste')
  assert.equal(racedLosers.length, 9)
  assert.equal(racedWinners[0].body.ciphertext, ciphertext)
  for (const loser of racedLosers) {
    assert.equal(loser.body.ciphertext, undefined)
  }

  const racedRow = readDatabaseRow(
    databasePath,
    'SELECT "ciphertext", "nonce", "salt", "kdf_params", "is_burned", "view_count" FROM "Paste" WHERE "slug" = ?',
    racedSlug
  )
  assert.deepEqual(
    { ...racedRow },
    { ciphertext: '', nonce: '', salt: null, kdf_params: null, is_burned: 1, view_count: 1 }
  )

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
  assert.equal(createFileShare.body.burn_after_read, false)
  assert.match(createFileShare.body.upload_token, /^[A-Za-z0-9_-]{43}$/)
  const uploadToken = createFileShare.body.upload_token

  const storedFileShare = readDatabaseRow(
    databasePath,
    'SELECT "upload_token_hash" FROM "FileShare" WHERE "slug" = ?',
    fileSlug
  )
  assert.match(storedFileShare.upload_token_hash, /^[0-9a-f]{64}$/)
  assert.notEqual(storedFileShare.upload_token_hash, uploadToken)

  const duplicateFileShare = await jsonRequest(baseUrl, '/api/file-shares', {
    slug: fileSlug,
    file_count: 1,
    total_size_bytes: 1,
  })
  assert.equal(duplicateFileShare.response.status, 409)

  const badSlugFileShare = await jsonRequest(baseUrl, '/api/file-shares', {
    slug: 'bad/slug',
    file_count: 1,
    total_size_bytes: 1,
  })
  assert.equal(badSlugFileShare.response.status, 400)

  // Old clients that do not send the upload token get a clear "update" error.
  const tokenlessChunk = await uploadChunk(baseUrl, fileSlug, fileId, 0, encryptedChunk)
  assert.equal(tokenlessChunk.response.status, 401)
  assert.match(tokenlessChunk.body.error, /upload token.*update/i)

  const wrongTokenChunk = await uploadChunk(
    baseUrl,
    fileSlug,
    fileId,
    0,
    encryptedChunk,
    'A'.repeat(43)
  )
  assert.equal(wrongTokenChunk.response.status, 403)

  const uploadedChunk = await uploadChunk(
    baseUrl,
    fileSlug,
    fileId,
    0,
    encryptedChunk,
    uploadToken
  )
  assert.equal(uploadedChunk.response.status, 204)

  const manifestCiphertext = Buffer.from('opaque manifest').toString('base64')
  const manifestBody = {
    manifest_ciphertext: manifestCiphertext,
    manifest_nonce: nonce,
  }

  const tokenlessComplete = await jsonRequest(
    baseUrl,
    `/api/file-shares/${fileSlug}/complete`,
    manifestBody
  )
  assert.equal(tokenlessComplete.response.status, 401)

  const wrongTokenComplete = await jsonRequest(
    baseUrl,
    `/api/file-shares/${fileSlug}/complete`,
    manifestBody,
    { 'x-upload-token': 'B'.repeat(43) }
  )
  assert.equal(wrongTokenComplete.response.status, 403)

  const completeFileShare = await jsonRequest(
    baseUrl,
    `/api/file-shares/${fileSlug}/complete`,
    manifestBody,
    { 'x-upload-token': uploadToken }
  )
  assert.equal(completeFileShare.response.status, 200)
  assert.equal(completeFileShare.body.slug, fileSlug)

  const lateChunk = await uploadChunk(
    baseUrl,
    fileSlug,
    fileId,
    1,
    encryptedChunk,
    uploadToken
  )
  assert.equal(lateChunk.response.status, 409)

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

  async function createCompletedFileShare({ burnAfterRead, headers = {}, base = baseUrl }) {
    const slug = `e2e-file-${randomUUID()}`
    const created = await jsonRequest(
      base,
      '/api/file-shares',
      {
        slug,
        file_count: 1,
        total_size_bytes: encryptedChunk.length,
        expires_in_hours: 1,
        burn_after_read: burnAfterRead,
      },
      headers
    )
    assert.equal(created.response.status, 201)
    assert.equal(created.body.burn_after_read, burnAfterRead)

    const uploaded = await uploadChunk(
      base,
      slug,
      fileId,
      0,
      encryptedChunk,
      created.body.upload_token
    )
    assert.equal(uploaded.response.status, 204)

    const completed = await jsonRequest(
      base,
      `/api/file-shares/${slug}/complete`,
      manifestBody,
      { 'x-upload-token': created.body.upload_token }
    )
    assert.equal(completed.response.status, 200)
    return slug
  }

  function downloadChunk(slug, grant, base = baseUrl) {
    return fetch(`${base}/api/file-shares/${slug}/chunks/${fileId}/0`, {
      headers: grant ? { 'x-download-grant': grant } : {},
    })
  }

  const burnFileSlug = await createCompletedFileShare({ burnAfterRead: true })

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const burnFileMeta = await request(baseUrl, `/api/file-shares/${burnFileSlug}/meta`)
    assert.equal(burnFileMeta.response.status, 200)
    assert.equal(burnFileMeta.body.burn_after_read, true)
    assert.equal(burnFileMeta.body.password_protected, false)
    assert.equal(burnFileMeta.body.file_count, 1)
    assert.equal(burnFileMeta.body.manifest_ciphertext, undefined)
  }

  // Chunks of an unopened burn share are not downloadable at all.
  const headFileShare = await fetch(`${baseUrl}/api/file-shares/${burnFileSlug}`, {
    method: 'HEAD',
  })
  assert.equal(headFileShare.status, 405)
  const headFileMeta = await fetch(`${baseUrl}/api/file-shares/${burnFileSlug}/meta`, {
    method: 'HEAD',
  })
  assert.equal(headFileMeta.status, 200)
  assert.equal(
    (await request(baseUrl, `/api/file-shares/${burnFileSlug}/meta`)).response.status,
    200
  )

  const prematureChunk = await downloadChunk(burnFileSlug)
  assert.equal(prematureChunk.status, 403)

  const burnManifest = await request(baseUrl, `/api/file-shares/${burnFileSlug}`)
  assert.equal(burnManifest.response.status, 200)
  assert.equal(burnManifest.body.manifest_ciphertext, manifestCiphertext)
  assert.equal(burnManifest.body.metadata.burn_after_read, true)
  assert.equal(burnManifest.body.metadata.is_burned, true)
  assert.match(burnManifest.body.download_grant, /^[A-Za-z0-9_-]{43}$/)
  const grantLifetimeMs =
    new Date(burnManifest.body.download_grant_expires_at).getTime() - Date.now()
  assert(grantLifetimeMs > 14 * 60 * 1000 && grantLifetimeMs <= 15 * 60 * 1000)
  const downloadGrant = burnManifest.body.download_grant

  const secondBurnManifest = await request(baseUrl, `/api/file-shares/${burnFileSlug}`)
  assert.equal(secondBurnManifest.response.status, 410)
  assert.equal(secondBurnManifest.body.error, 'File share has been burned')

  const burnedFileMeta = await request(baseUrl, `/api/file-shares/${burnFileSlug}/meta`)
  assert.equal(burnedFileMeta.response.status, 410)

  const burnedFileRow = readDatabaseRow(
    databasePath,
    'SELECT "manifest_ciphertext", "manifest_nonce", "is_burned", "download_grant_hash" FROM "FileShare" WHERE "slug" = ?',
    burnFileSlug
  )
  assert.equal(burnedFileRow.manifest_ciphertext, null)
  assert.equal(burnedFileRow.manifest_nonce, null)
  assert.equal(burnedFileRow.is_burned, 1)
  assert.notEqual(burnedFileRow.download_grant_hash, downloadGrant)

  const grantlessChunk = await downloadChunk(burnFileSlug)
  assert.equal(grantlessChunk.status, 403)

  const wrongGrantChunk = await downloadChunk(burnFileSlug, 'C'.repeat(43))
  assert.equal(wrongGrantChunk.status, 403)

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const grantedChunk = await downloadChunk(burnFileSlug, downloadGrant)
    assert.equal(grantedChunk.status, 200)
    assert.equal(grantedChunk.headers.get('cache-control'), 'no-store')
    assert.deepEqual(Buffer.from(await grantedChunk.arrayBuffer()), encryptedChunk)
  }

  const racedFileSlug = await createCompletedFileShare({ burnAfterRead: true })
  const racedManifests = await Promise.all(
    Array.from({ length: 10 }, () => request(baseUrl, `/api/file-shares/${racedFileSlug}`))
  )
  const racedManifestWinners = racedManifests.filter(
    ({ response }) => response.status === 200
  )
  assert.equal(racedManifestWinners.length, 1, 'exactly one reader may open a burn file share')
  assert.equal(
    racedManifests.filter(({ response }) => response.status === 410).length,
    9
  )

  // Account-owned shares: deleting a file share exercises the multi-id delete
  // query, and sign-out with a bearer token (used by the CLI logout) revokes it.
  const signUp = await jsonRequest(
    baseUrl,
    '/api/auth/sign-up/email',
    {
      name: 'E2E Owner',
      email: `owner-${randomUUID()}@example.com`,
      username: `owner_${randomUUID().slice(0, 8)}`,
      password: 'correct-horse-battery-staple',
    },
    { origin: baseUrl }
  )
  assert.equal(signUp.response.status, 200)
  const sessionToken = signUp.response.headers.get('set-auth-token') || signUp.body.token
  assert(sessionToken)
  const bearer = { authorization: `Bearer ${sessionToken}` }

  const ownedFileSlug = await createCompletedFileShare({
    burnAfterRead: true,
    headers: bearer,
  })
  const ownedShares = await request(baseUrl, '/api/account/shares?share_type=file_share', {
    headers: bearer,
  })
  assert.equal(ownedShares.response.status, 200)
  const ownedFileShare = ownedShares.body.shares.find((share) => share.slug === ownedFileSlug)
  assert(ownedFileShare)
  assert.equal(ownedFileShare.burn_after_read, true)
  assert.equal(ownedFileShare.status, 'active')

  const deleteOwnedShare = await request(
    baseUrl,
    `/api/account/shares/${ownedFileShare.id}`,
    { method: 'DELETE', headers: bearer }
  )
  assert.equal(deleteOwnedShare.response.status, 200)
  assert.equal(deleteOwnedShare.body.share.status, 'deleted')
  const deletedOwnedFile = await request(baseUrl, `/api/file-shares/${ownedFileSlug}/meta`)
  assert.equal(deletedOwnedFile.response.status, 404)

  const signOut = await request(baseUrl, '/api/auth/sign-out', {
    method: 'POST',
    headers: { ...bearer, 'content-type': 'application/json' },
    body: '{}',
  })
  assert.equal(signOut.response.status, 200)
  const revokedSession = await request(baseUrl, '/api/auth/get-session', {
    headers: bearer,
  })
  assert.equal(revokedSession.response.status, 200)
  assert.equal(revokedSession.body, null)

  const missingApiRoute = await request(baseUrl, '/api/e2e-missing')
  assert.equal(missingApiRoute.response.status, 404)
  assert.equal(missingApiRoute.body.error, 'Not Found')

  await stopServer(child)
  child = undefined

  // Download grants: a short idle window makes sliding extension, lazy purge
  // on expiry and the background purge observable within a few seconds.
  const grantPort = await reservePort()
  const grantBaseUrl = `http://127.0.0.1:${grantPort}`
  const grantDataDirectory = path.join(temporaryRoot, 'grant-data')
  child = startTestServer({
    port: grantPort,
    databasePath: path.join(temporaryRoot, 'grant.db'),
    dataDirectory: grantDataDirectory,
    environment: { FILE_SHARE_DOWNLOAD_GRANT_SECONDS: '2' },
  })
  await waitForServer(grantBaseUrl, child)
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
  const grantDatabasePath = path.join(temporaryRoot, 'grant.db')
  const shareRowCount = (slug) =>
    readDatabaseRow(
      grantDatabasePath,
      'SELECT COUNT(*) AS "count" FROM "FileShare" WHERE "slug" = ?',
      slug
    ).count
  const shareChunksExist = (slug) =>
    existsSync(path.join(grantDataDirectory, 'file-shares', slug))

  const slidingSlug = await createCompletedFileShare({
    burnAfterRead: true,
    base: grantBaseUrl,
  })
  const slidingOpen = await request(grantBaseUrl, `/api/file-shares/${slidingSlug}`)
  assert.equal(slidingOpen.response.status, 200)
  const slidingGrant = slidingOpen.body.download_grant
  const initialGrantLifetimeMs =
    new Date(slidingOpen.body.download_grant_expires_at).getTime() - Date.now()
  assert(initialGrantLifetimeMs > 0 && initialGrantLifetimeMs <= 2_000)

  // Each download within the idle window pushes the expiry forward, so the
  // share outlives its initial 2s window while it is being downloaded.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await sleep(1_200)
    const slidChunk = await downloadChunk(slidingSlug, slidingGrant, grantBaseUrl)
    assert.equal(slidChunk.status, 200, `sliding download ${attempt} should succeed`)
    await slidChunk.arrayBuffer()
  }

  // Once idle for longer than the window, the next request purges the share.
  await sleep(2_300)
  const expiredGrantChunk = await downloadChunk(slidingSlug, slidingGrant, grantBaseUrl)
  assert(
    [404, 410].includes(expiredGrantChunk.status),
    `expired grant returned ${expiredGrantChunk.status}`
  )
  assert.equal(shareRowCount(slidingSlug), 0)
  assert.equal(shareChunksExist(slidingSlug), false)

  // Without any further request, the background check purges a lapsed share.
  const idleSlug = await createCompletedFileShare({
    burnAfterRead: true,
    base: grantBaseUrl,
  })
  assert.equal(shareChunksExist(idleSlug), true)
  assert.equal(
    (await request(grantBaseUrl, `/api/file-shares/${idleSlug}`)).response.status,
    200
  )
  await sleep(4_000)
  assert.equal(shareRowCount(idleSlug), 0)
  assert.equal(shareChunksExist(idleSlug), false)

  await stopServer(child)
  child = undefined

  const anonymousPort = await reservePort()
  const anonymousBaseUrl = `http://127.0.0.1:${anonymousPort}`
  child = startTestServer({
    port: anonymousPort,
    databasePath: path.join(temporaryRoot, 'anonymous.db'),
    dataDirectory: path.join(temporaryRoot, 'anonymous-data'),
    environment: {
      DISABLE_AUTH: 'true',
    },
  })
  await waitForServer(anonymousBaseUrl, child)

  const anonymousCapabilities = await request(anonymousBaseUrl, '/api/capabilities')
  assert.equal(anonymousCapabilities.response.status, 200)
  assert.equal(anonymousCapabilities.body.auth.enabled, false)
  assert.equal(anonymousCapabilities.body.auth.signup_enabled, false)

  const disabledAuthRoute = await request(anonymousBaseUrl, '/api/auth/get-session')
  assert.equal(disabledAuthRoute.response.status, 404)

  const disabledAccountRoute = await request(anonymousBaseUrl, '/api/account/shares')
  assert.equal(disabledAccountRoute.response.status, 404)

  const anonymousPaste = await request(anonymousBaseUrl, '/api/pastes', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: `anonymous-${randomUUID()}`,
      ciphertext,
      nonce,
      burn_after_read: false,
    }),
  })
  assert.equal(anonymousPaste.response.status, 201)

  await stopServer(child)
  child = undefined

  const signupDisabledPort = await reservePort()
  const signupDisabledBaseUrl = `http://127.0.0.1:${signupDisabledPort}`
  child = startTestServer({
    port: signupDisabledPort,
    databasePath: path.join(temporaryRoot, 'signup-disabled.db'),
    dataDirectory: path.join(temporaryRoot, 'signup-disabled-data'),
    environment: {
      DISABLE_SIGNUP: 'true',
    },
  })
  await waitForServer(signupDisabledBaseUrl, child)

  const signupDisabledCapabilities = await request(
    signupDisabledBaseUrl,
    '/api/capabilities'
  )
  assert.equal(signupDisabledCapabilities.response.status, 200)
  assert.equal(signupDisabledCapabilities.body.auth.enabled, true)
  assert.equal(signupDisabledCapabilities.body.auth.signup_enabled, false)

  const availableSessionRoute = await request(
    signupDisabledBaseUrl,
    '/api/auth/get-session'
  )
  assert.equal(availableSessionRoute.response.status, 200)
  assert.equal(availableSessionRoute.body, null)

  const blockedSignup = await request(
    signupDisabledBaseUrl,
    '/api/auth/sign-up/email',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: signupDisabledBaseUrl,
      },
      body: JSON.stringify({
        name: 'E2E User',
        email: 'e2e@example.com',
        username: 'e2e_user',
        displayUsername: 'e2e_user',
        password: 'correct-horse-battery-staple',
      }),
    }
  )
  assert.equal(blockedSignup.response.status, 403)
  assert.equal(blockedSignup.body.code, 'SIGN_UP_DISABLED')

  console.log(
    'E2E smoke test passed: UI, shares, burn-after-read, upload tokens, anonymous mode, and sign-up controls'
  )
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
