// Cross-origin protections, token edge cases and audit coalescing. Runs on
// SQLite, or on Postgres when E2E_POSTGRES_URL is set.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { jsonRequest, nonce, request, runSuite, signUp, uploadChunk } from './lib/harness.mjs'

const EVIL_ORIGIN = 'https://evil.example'
const APP_ORIGIN = 'https://app.example'
const ciphertext = Buffer.from('opaque security-suite ciphertext').toString('base64')

function acao(result) {
  return result.response.headers.get('access-control-allow-origin')
}

await runSuite('e2e-security', { postgres: true }, async ({ startServer, provider }) => {
  // A plain `pastevault up` (migrations on by default) boots cleanly. On
  // SQLite there are no migrations to run, so nothing is attempted.
  const server = await startServer({
    label: 'security',
    migrations: true,
    environment: { CORS_ORIGIN: APP_ORIGIN },
  })
  const { baseUrl, database } = server
  assert.doesNotMatch(server.output(), /Migration failed|P3019/)

  // CORS: only the server's own origin and configured origins are allowed.
  const preflight = (origin) =>
    request(baseUrl, '/api/account/tokens', {
      method: 'OPTIONS',
      headers: {
        origin,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    })
  assert.equal(acao(await preflight(EVIL_ORIGIN)), null)
  assert.equal(acao(await preflight('null')), null)
  const trustedPreflight = await preflight(APP_ORIGIN)
  assert.equal(acao(trustedPreflight), APP_ORIGIN)
  assert.equal(trustedPreflight.response.headers.get('access-control-allow-credentials'), 'true')
  assert.equal(acao(await preflight(baseUrl)), baseUrl)
  const evilRead = await request(baseUrl, '/api/capabilities', { headers: { origin: EVIL_ORIGIN } })
  assert.equal(evilRead.response.status, 200)
  assert.equal(acao(evilRead), null)

  // CSRF: a cookie session can't make state-changing requests from another
  // origin. Bearer credentials and requests without an Origin are unaffected.
  const owner = await signUp(baseUrl, 'secowner')
  assert(owner.cookie.includes('session_token'), 'sign-up sets a session cookie')
  const cookie = { cookie: owner.cookie }
  const cookieMe = await request(baseUrl, '/api/me', { headers: cookie })
  assert.equal(cookieMe.response.status, 200)
  assert.equal(cookieMe.body.auth.kind, 'session')

  const mintFrom = (origin, headers = cookie) =>
    jsonRequest(baseUrl, '/api/account/tokens', { name: `from-${origin ?? 'none'}` }, {
      ...headers,
      ...(origin ? { origin } : {}),
    })

  for (const origin of [EVIL_ORIGIN, 'null', 'http://127.0.0.1:1']) {
    const blocked = await mintFrom(origin)
    assert.equal(blocked.response.status, 403, origin)
    assert.deepEqual(blocked.body, { error: 'origin_not_allowed' })
    assert.equal(acao(blocked), null)
  }
  const tokensAfterBlocked = await request(baseUrl, '/api/account/tokens', { headers: cookie })
  assert.deepEqual(tokensAfterBlocked.body.tokens, [])

  const sameOrigin = await mintFrom(baseUrl)
  assert.equal(sameOrigin.response.status, 201)
  assert.equal(acao(sameOrigin), baseUrl)
  assert.equal((await mintFrom(APP_ORIGIN)).response.status, 201)
  assert.equal((await mintFrom(undefined)).response.status, 201)
  const bearerFromEvil = await mintFrom(EVIL_ORIGIN, owner.headers)
  assert.equal(bearerFromEvil.response.status, 201)
  assert.equal(acao(bearerFromEvil), null)

  // Reads are allowed (nothing changes) but not readable cross-origin.
  const evilList = await request(baseUrl, '/api/account/tokens', {
    headers: { ...cookie, origin: EVIL_ORIGIN },
  })
  assert.equal(evilList.response.status, 200)
  assert.equal(acao(evilList), null)

  const revokeFrom = (origin) =>
    request(baseUrl, `/api/account/tokens/${sameOrigin.body.id}`, {
      method: 'DELETE',
      headers: { ...cookie, origin },
    })
  assert.equal((await revokeFrom(EVIL_ORIGIN)).response.status, 403)
  assert.equal((await revokeFrom(baseUrl)).response.status, 200)

  const evilPaste = await jsonRequest(
    baseUrl,
    '/api/pastes',
    { ciphertext, nonce },
    { ...cookie, origin: EVIL_ORIGIN }
  )
  assert.equal(evilPaste.response.status, 403)
  const ownedSlug = `sec-${randomUUID()}`
  assert.equal(
    (await jsonRequest(baseUrl, '/api/pastes', { slug: ownedSlug, ciphertext, nonce }, cookie))
      .response.status,
    201
  )
  const ownedList = await request(baseUrl, `/api/account/shares?slug=${ownedSlug}`, {
    headers: cookie,
  })
  assert.equal(ownedList.response.headers.get('cache-control'), 'no-store')
  const ownedShare = ownedList.body.shares[0]
  const evilDelete = await request(baseUrl, `/api/account/shares/${ownedShare.id}`, {
    method: 'DELETE',
    headers: { ...cookie, origin: EVIL_ORIGIN },
  })
  assert.equal(evilDelete.response.status, 403)
  assert.equal((await request(baseUrl, `/api/pastes/${ownedSlug}/meta`)).response.status, 200)

  // A bad API token is a 401 on every API route, not just the ones that use
  // the principal.
  const badToken = { authorization: `Bearer pv_pat_${'c'.repeat(52)}` }
  const fileCreate = await jsonRequest(baseUrl, '/api/file-shares', {
    slug: `sec-file-${randomUUID()}`,
    file_count: 1,
    total_size_bytes: 4,
  })
  const fileSlug = fileCreate.body.slug
  const uploadToken = fileCreate.body.upload_token
  for (const [method, pathname, body] of [
    ['GET', '/api/capabilities'],
    ['GET', `/api/pastes/${ownedSlug}/meta`],
    ['GET', `/api/file-shares/${fileSlug}/meta`],
    ['GET', `/api/file-shares/${fileSlug}/chunks/sec_file_0001/0`],
    ['PUT', `/api/file-shares/${fileSlug}/chunks/sec_file_0001/0`, Buffer.from('abcd')],
    ['POST', `/api/file-shares/${fileSlug}/complete`, JSON.stringify({})],
    ['GET', '/api/no-such-route'],
  ]) {
    const result = await request(baseUrl, pathname, {
      method,
      headers: {
        ...badToken,
        'x-upload-token': uploadToken,
        ...(body ? { 'content-type': Buffer.isBuffer(body) ? 'application/octet-stream' : 'application/json' } : {}),
      },
      body,
    })
    assert.equal(result.response.status, 401, `${method} ${pathname}`)
    assert.equal(result.body.error, 'invalid_token')
  }
  // Nothing happened on the share: the upload still works with a good request.
  assert.equal(
    (await uploadChunk(baseUrl, fileSlug, 'sec_file_0001', 0, Buffer.from('abcd'), uploadToken))
      .response.status,
    204
  )
  assert.equal((await request(baseUrl, `/api/pastes/${ownedSlug}/meta`)).response.status, 200)

  // Tokens bound to a revoked agent stop working, and /me never shows one.
  const agentId = `sec-agent-${randomUUID()}`
  const fingerprint = `pvk1_${'b'.repeat(32)}`
  await database.query(
    'INSERT INTO "AgentIdentity" ("id", "user_id", "name", "public_key", "fingerprint") VALUES ($1, $2, $3, $4, $5)',
    agentId,
    owner.user.id,
    'ci-agent',
    'A'.repeat(43),
    fingerprint
  )
  const agentToken = await jsonRequest(
    baseUrl,
    '/api/account/tokens',
    { name: 'agent-bound', agent_id: agentId },
    owner.headers
  )
  assert.equal(agentToken.response.status, 201)
  assert.equal(agentToken.body.agent_id, agentId)
  const agentHeaders = { authorization: `Bearer ${agentToken.body.token}` }
  const agentMe = await request(baseUrl, '/api/me', { headers: agentHeaders })
  assert.equal(agentMe.response.status, 200)
  assert.deepEqual(agentMe.body.auth.agent, { id: agentId, name: 'ci-agent', fingerprint })
  const listedAgentToken = (
    await request(baseUrl, '/api/account/tokens', { headers: owner.headers })
  ).body.tokens.find((token) => token.id === agentToken.body.id)
  assert.deepEqual(listedAgentToken.agent, { id: agentId, name: 'ci-agent' })

  await database.query(
    'UPDATE "AgentIdentity" SET "revoked_at" = "created_at" WHERE "id" = $1',
    agentId
  )
  const revokedAgentMe = await request(baseUrl, '/api/me', { headers: agentHeaders })
  assert.equal(revokedAgentMe.response.status, 401)
  assert.equal(revokedAgentMe.body.error, 'invalid_token')
  assert.equal(
    (
      await jsonRequest(
        baseUrl,
        '/api/account/tokens',
        { name: 'revoked-agent', agent_id: agentId },
        owner.headers
      )
    ).response.status,
    400
  )

  // Views of unlimited shares are coalesced per actor; view-limited shares log
  // every view.
  const ownerToken = await jsonRequest(baseUrl, '/api/account/tokens', { name: 'viewer' }, owner.headers)
  const unlimitedSlug = `sec-${randomUUID()}`
  assert.equal(
    (
      await jsonRequest(baseUrl, '/api/pastes', { slug: unlimitedSlug, ciphertext, nonce }, owner.headers)
    ).response.status,
    201
  )
  for (let index = 0; index < 3; index += 1) {
    assert.equal((await request(baseUrl, `/api/pastes/${unlimitedSlug}`)).response.status, 200)
  }
  assert.equal(
    (
      await request(baseUrl, `/api/pastes/${unlimitedSlug}`, {
        headers: { authorization: `Bearer ${ownerToken.body.token}` },
      })
    ).response.status,
    200
  )
  const unlimitedShare = (
    await request(baseUrl, `/api/account/shares?slug=${unlimitedSlug}`, { headers: owner.headers })
  ).body.shares[0]
  const unlimitedEvents = (
    await request(baseUrl, `/api/account/shares/${unlimitedShare.id}/events`, {
      headers: owner.headers,
    })
  ).body.events
  assert.deepEqual(
    unlimitedEvents.map((event) => [event.event, event.actor_kind]),
    [
      ['share.created', 'owner'],
      ['share.viewed', 'anonymous'],
      ['share.viewed', 'owner'],
    ]
  )
  assert.equal(unlimitedEvents[1].details.views, 3)
  assert.equal(unlimitedEvents[1].details.view, 3)
  assert.equal(unlimitedEvents[1].details.max_views, null)
  assert(unlimitedEvents[1].details.last_viewed_at)
  assert.equal(unlimitedEvents[2].details.views, 1)
  assert.equal(unlimitedEvents[2].details.view, 4)
  assert.equal(unlimitedEvents[2].actor_token_id, ownerToken.body.id)

  const limitedSlug = `sec-${randomUUID()}`
  await jsonRequest(
    baseUrl,
    '/api/pastes',
    { slug: limitedSlug, ciphertext, nonce, max_views: 3 },
    owner.headers
  )
  for (let index = 0; index < 3; index += 1) {
    await request(baseUrl, `/api/pastes/${limitedSlug}`)
  }
  const limitedShare = (
    await request(baseUrl, `/api/account/shares?slug=${limitedSlug}`, { headers: owner.headers })
  ).body.shares[0]
  const limitedEvents = (
    await request(baseUrl, `/api/account/shares/${limitedShare.id}/events`, {
      headers: owner.headers,
    })
  ).body.events
  assert.deepEqual(
    limitedEvents.filter((event) => event.event === 'share.viewed').map((event) => event.details),
    [
      { view: 1, max_views: 3 },
      { view: 2, max_views: 3 },
      { view: 3, max_views: 3 },
    ]
  )

  console.log(`E2E security test passed (${provider}): CORS, CSRF, bad tokens, revoked agents, audit coalescing`)
})
