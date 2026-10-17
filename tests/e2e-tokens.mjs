// API tokens, scopes, expires_in_minutes, max_views, raw-key recipients and the
// audit log. Runs on SQLite, or on Postgres when E2E_POSTGRES_URL is set.
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import {
  asBoolean,
  jsonRequest,
  nonce,
  request,
  runSuite,
  signUp,
  sleep,
  uploadChunk,
} from './lib/harness.mjs'

const ALL_SCOPES = [
  'shares:create',
  'shares:read',
  'shares:revoke',
  'shares:receive',
  'agents:read',
  'agents:write',
  'requests:create',
  'audit:read',
]
const DEFAULT_TOKEN_SCOPES = ALL_SCOPES.filter((scope) => scope !== 'agents:write')
const TOKEN_PATTERN = /^pv_pat_[a-z2-7]{52}$/
const ciphertext = Buffer.from('opaque token-suite ciphertext').toString('base64')
const encryptedChunk = Buffer.from('encrypted file chunk')
const manifestCiphertext = Buffer.from('opaque manifest').toString('base64')
const fileId = 'e2e_file_0001'

function bearer(token, userAgent) {
  return {
    authorization: `Bearer ${token}`,
    ...(userAgent ? { 'user-agent': userAgent } : {}),
  }
}

function assertWithin(actualIso, expectedMs, toleranceMs) {
  const delta = new Date(actualIso).getTime() - expectedMs
  assert(Math.abs(delta) <= toleranceMs, `timestamp ${actualIso} is off by ${delta}ms`)
}

function createPaste(baseUrl, fields = {}, headers = {}) {
  return jsonRequest(
    baseUrl,
    '/api/pastes',
    { slug: `tok-${randomUUID()}`, ciphertext, nonce, ...fields },
    headers
  )
}

async function createCompletedFileShare(baseUrl, fields = {}, headers = {}) {
  const slug = `tok-file-${randomUUID()}`
  const created = await jsonRequest(
    baseUrl,
    '/api/file-shares',
    { slug, file_count: 1, total_size_bytes: encryptedChunk.length, ...fields },
    headers
  )
  assert.equal(created.response.status, 201)
  assert.equal(
    (await uploadChunk(baseUrl, slug, fileId, 0, encryptedChunk, created.body.upload_token))
      .response.status,
    204
  )
  const completed = await jsonRequest(
    baseUrl,
    `/api/file-shares/${slug}/complete`,
    { manifest_ciphertext: manifestCiphertext, manifest_nonce: nonce },
    { 'x-upload-token': created.body.upload_token }
  )
  assert.equal(completed.response.status, 200)
  return { slug, created: created.body }
}

function downloadChunk(baseUrl, slug, grant) {
  return fetch(`${baseUrl}/api/file-shares/${slug}/chunks/${fileId}/0`, {
    headers: grant ? { 'x-download-grant': grant } : {},
  })
}

async function createToken(baseUrl, sessionHeaders, fields) {
  const created = await jsonRequest(baseUrl, '/api/account/tokens', fields, sessionHeaders)
  assert.equal(created.response.status, 201, JSON.stringify(created.body))
  assert.match(created.body.token, TOKEN_PATTERN)
  return created.body
}

async function listAllAuditEvents(baseUrl, headers, query = '') {
  const events = []
  let cursor
  do {
    const page = await request(
      baseUrl,
      `/api/account/audit?limit=200${query}${cursor ? `&cursor=${cursor}` : ''}`,
      { headers }
    )
    assert.equal(page.response.status, 200)
    events.push(...page.body.events)
    cursor = page.body.next_cursor
  } while (cursor)
  return events
}

// The tables as PR1 created them, before this change added columns.
function createLegacySqliteDatabase(databasePath) {
  const database = new DatabaseSync(databasePath)
  database.exec(`
    CREATE TABLE "Paste" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "slug" TEXT NOT NULL UNIQUE,
      "ciphertext" TEXT NOT NULL,
      "nonce" TEXT NOT NULL,
      "salt" TEXT,
      "kdf_params" TEXT,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
      "is_burned" BOOLEAN NOT NULL DEFAULT false,
      "view_count" INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE "FileShare" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "slug" TEXT NOT NULL UNIQUE,
      "manifest_ciphertext" TEXT,
      "manifest_nonce" TEXT,
      "salt" TEXT,
      "kdf_params" TEXT,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "is_complete" BOOLEAN NOT NULL DEFAULT false,
      "view_count" INTEGER NOT NULL DEFAULT 0,
      "file_count" INTEGER NOT NULL DEFAULT 0,
      "total_size_bytes" TEXT NOT NULL DEFAULT '0',
      "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
      "is_burned" BOOLEAN NOT NULL DEFAULT false,
      "upload_token_hash" TEXT,
      "download_grant_hash" TEXT,
      "download_grant_expires_at" TIMESTAMP,
      "burned_at" TIMESTAMP
    );
    CREATE TABLE "user" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "name" TEXT NOT NULL,
      "email" TEXT NOT NULL UNIQUE,
      "emailVerified" BOOLEAN NOT NULL DEFAULT false,
      "image" TEXT,
      "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "username" TEXT UNIQUE,
      "displayUsername" TEXT
    );
    CREATE TABLE "OwnedShare" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "user_id" TEXT NOT NULL,
      "share_type" TEXT NOT NULL,
      "resource_id" TEXT NOT NULL,
      "slug" TEXT NOT NULL,
      "status" TEXT NOT NULL,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "deleted_at" TIMESTAMP,
      "first_viewed_at" TIMESTAMP,
      "last_viewed_at" TIMESTAMP,
      "view_count" INTEGER NOT NULL DEFAULT 0,
      "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
      "file_count" INTEGER,
      "total_size_bytes" TEXT,
      "is_password_protected" BOOLEAN NOT NULL DEFAULT false,
      FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE
    );
  `)
  database
    .prepare(
      'INSERT INTO "Paste" ("id", "slug", "ciphertext", "nonce", "burn_after_read") VALUES (?, ?, ?, ?, 1)'
    )
    .run('legacy-burn-paste', 'legacy-burn-slug', ciphertext, nonce)
  database.close()
}

await runSuite('e2e-tokens', { postgres: true }, async ({ startServer, createDatabase, provider, temporaryRoot }) => {
  const server = await startServer({ label: 'tokens' })
  const { baseUrl, database } = server

  // Capabilities advertise only what this server implements.
  const capabilities = await request(baseUrl, '/api/capabilities')
  assert.equal(capabilities.response.status, 200)
  assert.equal(capabilities.body.api_version, 2)
  assert.deepEqual(capabilities.body.features, {
    expires_in_minutes: true,
    max_views: true,
    api_tokens: true,
    agents: true,
    sealed_shares: true,
    secret_requests: true,
    audit: true,
  })
  assert.equal(capabilities.body.limits.max_views, 1000)
  assert.equal(capabilities.body.limits.max_secret_request_bytes, 1048576)
  assert.equal(capabilities.body.limits.min_secret_request_ttl_seconds, 60)

  const owner = await signUp(baseUrl, 'owner')
  const session = owner.headers

  assert.equal((await request(baseUrl, '/api/me')).response.status, 401)

  const sessionMe = await request(baseUrl, '/api/me', { headers: session })
  assert.equal(sessionMe.response.status, 200)
  assert.equal(sessionMe.body.user.id, owner.user.id)
  assert.equal(sessionMe.body.auth.kind, 'session')
  assert.equal(sessionMe.body.auth.token_id, undefined)
  assert.deepEqual(sessionMe.body.auth.scopes, ALL_SCOPES)

  // Create a token with the defaults; it is shown exactly once.
  const createdToken = await createToken(baseUrl, session, { name: 'ci' })
  const token = createdToken.token
  assert.equal(createdToken.name, 'ci')
  assert.equal(createdToken.prefix, token.slice(0, 12))
  assert.deepEqual(createdToken.scopes, DEFAULT_TOKEN_SCOPES)
  assert.equal(createdToken.agent_id, null)
  assertWithin(createdToken.expires_at, Date.now() + 90 * 86_400_000, 60_000)
  const tokenHeaders = bearer(token, 'pastevault/9.9.9')

  // Only the SHA-256 is stored.
  const [storedToken] = await database.query(
    'SELECT * FROM "ApiToken" WHERE "id" = $1',
    createdToken.id
  )
  assert.equal(storedToken.token_hash, createHash('sha256').update(token).digest('hex'))
  assert.equal(storedToken.token_prefix, token.slice(0, 12))
  assert(!JSON.stringify(storedToken).includes(token.slice(12)))

  const tokenMe = await request(baseUrl, '/api/me', { headers: tokenHeaders })
  assert.equal(tokenMe.response.status, 200)
  assert.equal(tokenMe.body.user.id, owner.user.id)
  assert.equal(tokenMe.body.auth.kind, 'token')
  assert.equal(tokenMe.body.auth.token_id, createdToken.id)
  assert.deepEqual(tokenMe.body.auth.scopes, DEFAULT_TOKEN_SCOPES)
  assert.equal(tokenMe.body.auth.agent, undefined)

  // Tokens can't manage tokens.
  const tokenMintsToken = await jsonRequest(baseUrl, '/api/account/tokens', { name: 'x' }, tokenHeaders)
  assert.equal(tokenMintsToken.response.status, 403)
  assert.equal(tokenMintsToken.body.error, 'session_required')
  assert.equal(
    (await request(baseUrl, '/api/account/tokens', { headers: tokenHeaders })).response.status,
    403
  )
  assert.equal(
    (
      await request(baseUrl, `/api/account/tokens/${createdToken.id}`, {
        method: 'DELETE',
        headers: tokenHeaders,
      })
    ).response.status,
    403
  )

  // Tokens never reach better-auth.
  const tokenOnAuth = await request(baseUrl, '/api/auth/get-session', { headers: tokenHeaders })
  assert.equal(tokenOnAuth.response.status, 401)
  assert.equal(tokenOnAuth.body.error, 'invalid_token')
  const tokenSignOut = await request(baseUrl, '/api/auth/sign-out', {
    method: 'POST',
    headers: { ...tokenHeaders, 'content-type': 'application/json' },
    body: '{}',
  })
  assert.equal(tokenSignOut.response.status, 401)

  // Unknown or malformed tokens are 401, never a silent anonymous create.
  for (const badToken of ['pv_pat_short', `pv_pat_${'a'.repeat(52)}`]) {
    const badMe = await request(baseUrl, '/api/me', { headers: bearer(badToken) })
    assert.equal(badMe.response.status, 401)
    assert.equal(badMe.body.error, 'invalid_token')
    const slug = `tok-${randomUUID()}`
    const badCreate = await createPaste(baseUrl, { slug }, bearer(badToken))
    assert.equal(badCreate.response.status, 401)
    assert.equal((await request(baseUrl, `/api/pastes/${slug}/meta`)).response.status, 404)
  }

  // A token creates an owned paste; expires_in_minutes sets a short expiry.
  const minutesSlug = `tok-${randomUUID()}`
  const minutesPaste = await createPaste(
    baseUrl,
    { slug: minutesSlug, expires_in_minutes: 15 },
    tokenHeaders
  )
  assert.equal(minutesPaste.response.status, 201)
  assert.equal(minutesPaste.body.max_views, null)
  assertWithin(minutesPaste.body.expires_at, Date.now() + 15 * 60_000, 30_000)

  const ownedBySlug = await request(baseUrl, `/api/account/shares?slug=${minutesSlug}`, {
    headers: tokenHeaders,
  })
  assert.equal(ownedBySlug.response.status, 200)
  assert.equal(ownedBySlug.body.shares.length, 1)
  assert.equal(ownedBySlug.body.next_cursor, null)
  const minutesShare = ownedBySlug.body.shares[0]
  assert.equal(minutesShare.slug, minutesSlug)
  assert.equal(minutesShare.max_views, null)
  assert.equal(minutesShare.recipient_fingerprint, null)
  assert.equal(minutesShare.recipient_agent_name, null)
  const [minutesOwnedRow] = await database.query(
    'SELECT "created_via_token_id" FROM "OwnedShare" WHERE "id" = $1',
    minutesShare.id
  )
  assert.equal(minutesOwnedRow.created_via_token_id, createdToken.id)

  for (const invalid of [
    { expires_in_minutes: 15, expires_in_hours: 1 },
    { expires_in_minutes: 0 },
    { expires_in_minutes: 525601 },
    { expires_in_minutes: 1.5 },
    { max_views: 0 },
    { max_views: 1001 },
    { burn_after_read: true, max_views: 3 },
  ]) {
    const rejected = await createPaste(baseUrl, invalid)
    assert.equal(rejected.response.status, 400, JSON.stringify(invalid))
  }
  const bothExpiries = await createPaste(baseUrl, { expires_in_minutes: 5, expires_in_hours: 1 })
  assert.match(bothExpiries.body.error, /mutually exclusive/)

  // max_views=2: two reads, the second wipes the content, the third is gone.
  const limitedSlug = `tok-${randomUUID()}`
  const limited = await createPaste(baseUrl, { slug: limitedSlug, max_views: 2 }, session)
  assert.equal(limited.response.status, 201)
  assert.equal(limited.body.max_views, 2)

  const limitedMeta = await request(baseUrl, `/api/pastes/${limitedSlug}/meta`)
  assert.equal(limitedMeta.response.status, 200)
  assert.equal(limitedMeta.body.max_views, 2)
  assert.equal(limitedMeta.body.views_remaining, 2)
  assert.equal(limitedMeta.body.burn_after_read, false)
  assert.equal(limitedMeta.body.recipient, null)
  assert.equal(limitedMeta.body.requires_recipient_auth, false)

  const firstLimitedRead = await request(baseUrl, `/api/pastes/${limitedSlug}`)
  assert.equal(firstLimitedRead.response.status, 200)
  assert.equal(firstLimitedRead.body.ciphertext, ciphertext)
  assert.equal(firstLimitedRead.body.metadata.view_count, 1)
  assert.equal(firstLimitedRead.body.metadata.views_remaining, 1)
  assert.equal(firstLimitedRead.body.metadata.is_burned, false)
  assert.equal(firstLimitedRead.response.headers.get('cache-control'), 'no-store')
  assert.equal(
    (await request(baseUrl, `/api/pastes/${limitedSlug}/meta`)).body.views_remaining,
    1
  )

  const secondLimitedRead = await request(baseUrl, `/api/pastes/${limitedSlug}`, {
    headers: tokenHeaders,
  })
  assert.equal(secondLimitedRead.response.status, 200)
  assert.equal(secondLimitedRead.body.ciphertext, ciphertext)
  assert.equal(secondLimitedRead.body.metadata.view_count, 2)
  assert.equal(secondLimitedRead.body.metadata.views_remaining, 0)
  assert.equal(secondLimitedRead.body.metadata.is_burned, true)

  const [wipedPaste] = await database.query(
    'SELECT "ciphertext", "nonce", "salt", "is_burned", "view_count" FROM "Paste" WHERE "slug" = $1',
    limitedSlug
  )
  assert.equal(wipedPaste.ciphertext, '')
  assert.equal(wipedPaste.nonce, '')
  assert.equal(wipedPaste.salt, null)
  assert.equal(asBoolean(wipedPaste.is_burned), true)
  assert.equal(Number(wipedPaste.view_count), 2)

  const thirdLimitedRead = await request(baseUrl, `/api/pastes/${limitedSlug}`)
  assert.equal(thirdLimitedRead.response.status, 410)
  assert.equal(thirdLimitedRead.body.ciphertext, undefined)
  assert.equal((await request(baseUrl, `/api/pastes/${limitedSlug}/meta`)).response.status, 410)

  // Concurrent readers never get more than max_views views between them.
  const racedSlug = `tok-${randomUUID()}`
  assert.equal((await createPaste(baseUrl, { slug: racedSlug, max_views: 3 })).response.status, 201)
  const racedReads = await Promise.all(
    Array.from({ length: 10 }, () => request(baseUrl, `/api/pastes/${racedSlug}`))
  )
  assert.equal(racedReads.filter(({ response }) => response.status === 200).length, 3)
  assert.equal(racedReads.filter(({ response }) => response.status === 410).length, 7)

  // burn_after_read and max_views=1 are the same thing.
  const burnSlug = `tok-${randomUUID()}`
  assert.equal(
    (await createPaste(baseUrl, { slug: burnSlug, burn_after_read: true })).body.max_views,
    1
  )
  assert.equal((await request(baseUrl, `/api/pastes/${burnSlug}/meta`)).body.max_views, 1)
  const oneViewSlug = `tok-${randomUUID()}`
  assert.equal((await createPaste(baseUrl, { slug: oneViewSlug, max_views: 1 })).response.status, 201)
  assert.equal(
    (await request(baseUrl, `/api/pastes/${oneViewSlug}/meta`)).body.burn_after_read,
    true
  )

  // File share with max_views=2: the first open leaves chunks readable, the
  // final open burns it and hands out the download grant.
  const limitedFile = await createCompletedFileShare(baseUrl, { max_views: 2 }, session)
  assert.equal(limitedFile.created.max_views, 2)
  assert.equal(limitedFile.created.burn_after_read, false)
  assert.equal((await downloadChunk(baseUrl, limitedFile.slug)).status, 403)

  const limitedFileMeta = await request(baseUrl, `/api/file-shares/${limitedFile.slug}/meta`)
  assert.equal(limitedFileMeta.body.max_views, 2)
  assert.equal(limitedFileMeta.body.views_remaining, 2)

  const firstOpen = await request(baseUrl, `/api/file-shares/${limitedFile.slug}`)
  assert.equal(firstOpen.response.status, 200)
  assert.equal(firstOpen.body.manifest_ciphertext, manifestCiphertext)
  assert.equal(firstOpen.body.metadata.is_burned, false)
  assert.equal(firstOpen.body.metadata.views_remaining, 1)
  assert.equal(firstOpen.body.download_grant, undefined)
  const openChunk = await downloadChunk(baseUrl, limitedFile.slug)
  assert.equal(openChunk.status, 200)
  assert.equal(openChunk.headers.get('cache-control'), 'no-store')
  assert.deepEqual(Buffer.from(await openChunk.arrayBuffer()), encryptedChunk)

  const finalOpen = await request(baseUrl, `/api/file-shares/${limitedFile.slug}`)
  assert.equal(finalOpen.response.status, 200)
  assert.equal(finalOpen.body.manifest_ciphertext, manifestCiphertext)
  assert.equal(finalOpen.body.metadata.is_burned, true)
  assert.equal(finalOpen.body.metadata.views_remaining, 0)
  assert.match(finalOpen.body.download_grant, /^[A-Za-z0-9_-]{43}$/)
  assert.equal((await downloadChunk(baseUrl, limitedFile.slug)).status, 403)
  const grantedChunk = await downloadChunk(baseUrl, limitedFile.slug, finalOpen.body.download_grant)
  assert.equal(grantedChunk.status, 200)
  assert.deepEqual(Buffer.from(await grantedChunk.arrayBuffer()), encryptedChunk)
  assert.equal(
    (await request(baseUrl, `/api/file-shares/${limitedFile.slug}`)).response.status,
    410
  )
  const [wipedFile] = await database.query(
    'SELECT "manifest_ciphertext", "is_burned", "view_count" FROM "FileShare" WHERE "slug" = $1',
    limitedFile.slug
  )
  assert.equal(wipedFile.manifest_ciphertext, null)
  assert.equal(asBoolean(wipedFile.is_burned), true)
  assert.equal(Number(wipedFile.view_count), 2)

  // Concurrent openers of a view-limited file share: exactly max_views of them
  // get the manifest, and only the one that took the last view gets a grant.
  const racedFile = await createCompletedFileShare(baseUrl, { max_views: 3 })
  const racedOpens = await Promise.all(
    Array.from({ length: 20 }, () => request(baseUrl, `/api/file-shares/${racedFile.slug}`))
  )
  const racedOpenWinners = racedOpens.filter(({ response }) => response.status === 200)
  assert.equal(racedOpenWinners.length, 3)
  assert.equal(racedOpens.filter(({ response }) => response.status === 410).length, 17)
  assert(racedOpenWinners.every(({ body }) => body.manifest_ciphertext === manifestCiphertext))
  const racedGrants = racedOpenWinners.filter(({ body }) => body.download_grant)
  assert.equal(racedGrants.length, 1)
  assert.equal(racedGrants[0].body.metadata.is_burned, true)
  assert.deepEqual(
    racedOpenWinners.map(({ body }) => body.metadata.view_count).sort(),
    [1, 2, 3]
  )
  assert.equal(
    (await downloadChunk(baseUrl, racedFile.slug, racedGrants[0].body.download_grant)).status,
    200
  )

  // Raw-key recipients are stored and returned; agent recipients come later.
  const fingerprint = `pvk1_${'a'.repeat(32)}`
  const wrappedKey = 'A'.repeat(140)
  const sealedSlug = `tok-${randomUUID()}`
  const sealed = await createPaste(baseUrl, {
    slug: sealedSlug,
    recipient: { fingerprint, wrapped_key: wrappedKey },
  })
  assert.equal(sealed.response.status, 201)
  assert.equal(sealed.body.max_views, 1)
  const sealedMeta = await request(baseUrl, `/api/pastes/${sealedSlug}/meta`)
  assert.deepEqual(sealedMeta.body.recipient, { fingerprint })
  assert.equal(sealedMeta.body.requires_recipient_auth, false)
  assert.equal(sealedMeta.body.max_views, 1)
  assert.equal(sealedMeta.body.wrapped_key, undefined)
  const sealedRead = await request(baseUrl, `/api/pastes/${sealedSlug}`)
  assert.equal(sealedRead.response.status, 200)
  assert.equal(sealedRead.body.wrapped_key, wrappedKey)
  assert.equal(sealedRead.body.recipient_fingerprint, fingerprint)
  const [wipedSealed] = await database.query(
    'SELECT "wrapped_key" FROM "Paste" WHERE "slug" = $1',
    sealedSlug
  )
  assert.equal(wipedSealed.wrapped_key, null)

  for (const invalidRecipient of [
    { recipient: { fingerprint, wrapped_key: wrappedKey }, salt: 'c2FsdA' },
    { recipient: { fingerprint: 'pvk1_short', wrapped_key: wrappedKey } },
    { recipient: { fingerprint, wrapped_key: 'short' } },
  ]) {
    assert.equal((await createPaste(baseUrl, invalidRecipient)).response.status, 400)
  }
  const agentRecipient = await createPaste(
    baseUrl,
    { recipient: { agent_id: 'agent-1', fingerprint, wrapped_key: wrappedKey } },
    session
  )
  // Agents of another account (or unknown ones) can't be recipients;
  // tests/e2e-agents.mjs covers sealing to the account's own agents.
  assert.equal(agentRecipient.response.status, 400)
  assert.equal(agentRecipient.body.code, 'recipient_agent_unknown')

  const sealedFile = await createCompletedFileShare(baseUrl, {
    recipient: { fingerprint, wrapped_key: wrappedKey },
  })
  assert.equal(sealedFile.created.max_views, 1)
  const sealedFileOpen = await request(baseUrl, `/api/file-shares/${sealedFile.slug}`)
  assert.equal(sealedFileOpen.body.wrapped_key, wrappedKey)
  assert.equal(sealedFileOpen.body.recipient_fingerprint, fingerprint)

  // Scopes.
  const readOnly = await createToken(baseUrl, session, {
    name: 'read-only',
    scopes: ['shares:read'],
    expires_in_days: null,
  })
  assert.equal(readOnly.expires_at, null)
  assert.deepEqual(readOnly.scopes, ['shares:read'])
  const readOnlyHeaders = bearer(readOnly.token)

  const readOnlyCreate = await createPaste(baseUrl, {}, readOnlyHeaders)
  assert.equal(readOnlyCreate.response.status, 403)
  assert.deepEqual(readOnlyCreate.body, { error: 'insufficient_scope', required: 'shares:create' })
  const readOnlyFile = await jsonRequest(
    baseUrl,
    '/api/file-shares',
    { file_count: 1, total_size_bytes: 1 },
    readOnlyHeaders
  )
  assert.equal(readOnlyFile.response.status, 403)
  assert.equal(
    (await request(baseUrl, '/api/account/shares', { headers: readOnlyHeaders })).response.status,
    200
  )
  const readOnlyAudit = await request(baseUrl, '/api/account/audit', { headers: readOnlyHeaders })
  assert.equal(readOnlyAudit.response.status, 403)
  assert.equal(readOnlyAudit.body.required, 'audit:read')
  const readOnlyDelete = await request(baseUrl, `/api/account/shares/${minutesShare.id}`, {
    method: 'DELETE',
    headers: readOnlyHeaders,
  })
  assert.equal(readOnlyDelete.response.status, 403)
  assert.equal(readOnlyDelete.body.required, 'shares:revoke')

  for (const invalidToken of [
    { name: '' },
    { name: 'x', scopes: ['shares:everything'] },
    { name: 'x', scopes: [] },
    { name: 'x', expires_in_days: 0 },
    { name: 'x', expires_in_days: 366 },
    { name: 'x', agent_id: 'no-such-agent' },
    { name: 'x', token: 'pv_pat_chosen' },
  ]) {
    const rejected = await jsonRequest(baseUrl, '/api/account/tokens', invalidToken, session)
    assert.equal(rejected.response.status, 400, JSON.stringify(invalidToken))
  }

  // A token with shares:revoke revokes an owned share.
  const revokeSlug = `tok-${randomUUID()}`
  assert.equal((await createPaste(baseUrl, { slug: revokeSlug }, tokenHeaders)).response.status, 201)
  const revokeTarget = (
    await request(baseUrl, `/api/account/shares?slug=${revokeSlug}`, { headers: tokenHeaders })
  ).body.shares[0]
  const revokedShare = await request(baseUrl, `/api/account/shares/${revokeTarget.id}`, {
    method: 'DELETE',
    headers: tokenHeaders,
  })
  assert.equal(revokedShare.response.status, 200)
  assert.equal(revokedShare.body.share.status, 'deleted')
  assert.equal((await request(baseUrl, `/api/pastes/${revokeSlug}/meta`)).response.status, 404)

  // Owned-share listing pages with a cursor.
  const allShares = await request(baseUrl, '/api/account/shares', { headers: session })
  assert.equal(allShares.body.next_cursor, null)
  const pagedShareIds = []
  let shareCursor
  do {
    const page = await request(
      baseUrl,
      `/api/account/shares?limit=2${shareCursor ? `&cursor=${shareCursor}` : ''}`,
      { headers: session }
    )
    assert.equal(page.response.status, 200)
    assert(page.body.shares.length <= 2)
    pagedShareIds.push(...page.body.shares.map((share) => share.id))
    shareCursor = page.body.next_cursor
  } while (shareCursor)
  assert.deepEqual(pagedShareIds, allShares.body.shares.map((share) => share.id))
  assert.equal(
    (await request(baseUrl, '/api/account/shares?cursor=not-a-cursor', { headers: session }))
      .response.status,
    400
  )

  // Per-share events, in order.
  const limitedShare = (
    await request(baseUrl, `/api/account/shares?slug=${limitedSlug}`, { headers: session })
  ).body.shares[0]
  assert.equal(limitedShare.max_views, 2)
  assert.equal(limitedShare.status, 'burned')
  const limitedEvents = await request(baseUrl, `/api/account/shares/${limitedShare.id}/events`, {
    headers: tokenHeaders,
  })
  assert.equal(limitedEvents.response.status, 200)
  assert.deepEqual(
    limitedEvents.body.events.map((event) => event.event),
    ['share.created', 'share.viewed', 'share.viewed', 'share.burned']
  )
  const [createdEvent, anonymousView, ownerView] = limitedEvents.body.events
  assert.equal(createdEvent.actor_kind, 'owner')
  assert.equal(createdEvent.actor_token_id, null)
  assert.equal(createdEvent.subject_type, 'paste')
  assert.equal(createdEvent.subject_id, limitedShare.id)
  assert.equal(createdEvent.slug, limitedSlug)
  assert.equal(anonymousView.actor_kind, 'anonymous')
  assert.deepEqual(anonymousView.details, { view: 1, max_views: 2 })
  assert.equal(anonymousView.ip_prefix, null)
  assert.equal(ownerView.actor_kind, 'owner')
  assert.equal(ownerView.actor_token_id, createdToken.id)
  assert.equal(ownerView.client, 'pastevault-cli/9.9.9')
  assert.deepEqual(ownerView.details, { view: 2, max_views: 2 })

  const fileShareEvents = await request(
    baseUrl,
    `/api/account/shares/${
      (
        await request(baseUrl, `/api/account/shares?slug=${limitedFile.slug}`, { headers: session })
      ).body.shares[0].id
    }/events`,
    { headers: session }
  )
  assert.deepEqual(
    fileShareEvents.body.events.map((event) => event.event),
    ['share.created', 'share.viewed', 'share.viewed', 'share.burned', 'share.download_granted']
  )

  // Token revocation and expiry.
  const revokedToken = await request(baseUrl, `/api/account/tokens/${createdToken.id}`, {
    method: 'DELETE',
    headers: session,
  })
  assert.equal(revokedToken.response.status, 200)
  assert(revokedToken.body.token.revoked_at)
  assert.equal(revokedToken.body.token.prefix, createdToken.prefix)
  for (const pathname of ['/api/me', '/api/account/shares']) {
    const afterRevoke = await request(baseUrl, pathname, { headers: tokenHeaders })
    assert.equal(afterRevoke.response.status, 401)
    assert.equal(afterRevoke.body.error, 'invalid_token')
  }
  assert.equal((await createPaste(baseUrl, {}, tokenHeaders)).response.status, 401)
  const revokedAgain = await request(baseUrl, `/api/account/tokens/${createdToken.id}`, {
    method: 'DELETE',
    headers: session,
  })
  assert.equal(revokedAgain.response.status, 200)
  assert.equal(revokedAgain.body.token.revoked_at, revokedToken.body.token.revoked_at)

  const expiring = await createToken(baseUrl, session, { name: 'expiring', expires_in_days: 1 })
  assert.equal(
    (await request(baseUrl, '/api/me', { headers: bearer(expiring.token) })).response.status,
    200
  )
  await sleep(20)
  await database.query(
    'UPDATE "ApiToken" SET "expires_at" = "created_at" WHERE "id" = $1',
    expiring.id
  )
  const expiredMe = await request(baseUrl, '/api/me', { headers: bearer(expiring.token) })
  assert.equal(expiredMe.response.status, 401)
  assert.equal(expiredMe.body.error, 'invalid_token')

  const tokenList = await request(baseUrl, '/api/account/tokens', { headers: session })
  assert.equal(tokenList.response.status, 200)
  assert.deepEqual(
    tokenList.body.tokens.map((listed) => listed.name),
    ['expiring', 'read-only', 'ci']
  )
  const listedCi = tokenList.body.tokens.find((listed) => listed.id === createdToken.id)
  assert(listedCi.last_used_at)
  assert(listedCi.revoked_at)
  assert.equal(listedCi.agent, null)
  for (const listed of tokenList.body.tokens) {
    assert.equal(listed.token, undefined)
    assert.equal(listed.token_hash, undefined)
  }

  // The account audit log, paged, filtered and complete.
  const allEvents = await listAllAuditEvents(baseUrl, session)
  const eventNames = new Set(allEvents.map((event) => event.event))
  for (const expected of [
    'share.created',
    'share.viewed',
    'share.burned',
    'share.download_granted',
    'share.revoked',
    'token.created',
    'token.revoked',
  ]) {
    assert(eventNames.has(expected), `missing ${expected}`)
  }
  assert.equal(allEvents.filter((event) => event.event === 'token.created').length, 3)
  assert.equal(allEvents.filter((event) => event.event === 'token.revoked').length, 1)
  const tokenCreatedEvent = allEvents.find(
    (event) => event.event === 'token.created' && event.subject_id === createdToken.id
  )
  assert.equal(tokenCreatedEvent.subject_type, 'token')
  assert.equal(tokenCreatedEvent.details.prefix, createdToken.prefix)
  assert(!JSON.stringify(allEvents).includes(token.slice(12)))
  const revokeEvent = allEvents.find((event) => event.event === 'share.revoked')
  assert.equal(revokeEvent.actor_token_id, createdToken.id)
  assert.equal(revokeEvent.slug, revokeSlug)
  for (let index = 1; index < allEvents.length; index += 1) {
    assert(allEvents[index - 1].created_at >= allEvents[index].created_at, 'newest first')
  }

  const pagedEvents = []
  let auditCursor
  do {
    const page = await request(
      baseUrl,
      `/api/account/audit?limit=3${auditCursor ? `&cursor=${auditCursor}` : ''}`,
      { headers: session }
    )
    assert(page.body.events.length <= 3)
    pagedEvents.push(...page.body.events)
    auditCursor = page.body.next_cursor
  } while (auditCursor)
  assert.deepEqual(
    pagedEvents.map((event) => event.id),
    allEvents.map((event) => event.id)
  )

  const burnedOnly = await listAllAuditEvents(baseUrl, session, '&event=share.burned')
  assert(burnedOnly.length >= 2)
  assert(burnedOnly.every((event) => event.event === 'share.burned'))
  assert.equal((await listAllAuditEvents(baseUrl, session, '&since=1h')).length, allEvents.length)
  assert.equal(
    (await listAllAuditEvents(baseUrl, session, '&since=2099-01-01T00:00:00Z')).length,
    0
  )
  for (const badQuery of ['since=yesterday', 'limit=0', 'limit=201', 'event=DROP', 'cursor=@@']) {
    assert.equal(
      (await request(baseUrl, `/api/account/audit?${badQuery}`, { headers: session })).response
        .status,
      400,
      badQuery
    )
  }

  // Another account sees none of it.
  const stranger = await signUp(baseUrl, 'stranger')
  assert.equal(
    (await request(baseUrl, `/api/account/shares/${limitedShare.id}/events`, { headers: stranger.headers }))
      .response.status,
    404
  )
  assert.equal(
    (await request(baseUrl, `/api/account/tokens/${readOnly.id}`, {
      method: 'DELETE',
      headers: stranger.headers,
    })).response.status,
    404
  )
  assert.deepEqual(
    (await request(baseUrl, '/api/account/audit', { headers: stranger.headers })).body.events,
    []
  )
  assert.deepEqual(
    (await request(baseUrl, '/api/account/tokens', { headers: stranger.headers })).body.tokens,
    []
  )

  await server.stop()

  // AUDIT_IP_MODE=truncated stores the /24 only.
  const ipServer = await startServer({
    label: 'audit-ip',
    environment: { AUDIT_IP_MODE: 'truncated' },
  })
  const ipOwner = await signUp(ipServer.baseUrl, 'ipowner')
  assert.equal((await createPaste(ipServer.baseUrl, {}, ipOwner.headers)).response.status, 201)
  const ipEvents = await request(ipServer.baseUrl, '/api/account/audit', { headers: ipOwner.headers })
  assert.equal(ipEvents.body.events[0].event, 'share.created')
  assert.equal(ipEvents.body.events[0].ip_prefix, '127.0.0.0/24')
  await ipServer.stop()

  // DISABLE_AUTH: account features are absent; share features still work.
  const anonymous = await startServer({ label: 'no-auth', environment: { DISABLE_AUTH: 'true' } })
  for (const pathname of [
    '/api/me',
    '/api/account/tokens',
    '/api/account/audit',
    `/api/account/shares/${limitedShare.id}/events`,
    '/api/agents',
    '/api/account/secret-requests',
    '/api/secret-requests/by-code/ABCD-EFGH',
  ]) {
    assert.equal((await request(anonymous.baseUrl, pathname)).response.status, 404, pathname)
  }
  const anonymousCapabilities = await request(anonymous.baseUrl, '/api/capabilities')
  assert.deepEqual(anonymousCapabilities.body.features, {
    expires_in_minutes: true,
    max_views: true,
    api_tokens: false,
    agents: false,
    // Sealing to a raw public key (--to-key) needs no accounts.
    sealed_shares: true,
    secret_requests: false,
    audit: false,
  })
  const anonymousSlug = `tok-${randomUUID()}`
  const anonymousPaste = await createPaste(
    anonymous.baseUrl,
    { slug: anonymousSlug, expires_in_minutes: 5, max_views: 2 },
    bearer(`pv_pat_${'b'.repeat(52)}`)
  )
  assert.equal(anonymousPaste.response.status, 201)
  assert.equal(anonymousPaste.body.max_views, 2)
  assert.equal(
    (await request(anonymous.baseUrl, `/api/pastes/${anonymousSlug}`)).body.metadata.views_remaining,
    1
  )
  await anonymous.stop()

  // SQLite databases from before this change gain the new columns at boot,
  // and legacy burn-after-read rows keep their one view.
  if (provider === 'sqlite') {
    const legacyPath = path.join(temporaryRoot, 'legacy.db')
    createLegacySqliteDatabase(legacyPath)
    const legacy = await startServer({
      label: 'legacy',
      database: await createDatabase('legacy', { sqlitePath: legacyPath }),
    })
    const legacyMeta = await request(legacy.baseUrl, '/api/pastes/legacy-burn-slug/meta')
    assert.equal(legacyMeta.response.status, 200)
    assert.equal(legacyMeta.body.max_views, 1)
    assert.equal(legacyMeta.body.views_remaining, 1)
    assert.equal(
      (await request(legacy.baseUrl, '/api/pastes/legacy-burn-slug')).body.metadata.is_burned,
      true
    )
    assert.equal(
      (await request(legacy.baseUrl, '/api/pastes/legacy-burn-slug')).response.status,
      410
    )
    const legacyOwner = await signUp(legacy.baseUrl, 'legacy')
    assert.equal(
      (await createPaste(legacy.baseUrl, { max_views: 3 }, legacyOwner.headers)).response.status,
      201
    )
    const [ownedColumns] = await legacy.database.query(
      'SELECT COUNT(*) AS "count" FROM pragma_table_info(\'OwnedShare\') WHERE "name" IN (\'max_views\', \'created_via_token_id\')'
    )
    assert.equal(Number(ownedColumns.count), 2)
    await legacy.stop()
  }

  console.log(`E2E tokens test passed (${provider}): tokens, scopes, minutes, max_views, recipients, audit`)
})
