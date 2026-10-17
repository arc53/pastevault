// Agent identities and sealed shares end to end: the Go CLI's agent init,
// put --to / --to-key and get against a real server, the agents API,
// recipient auth on consuming GETs, key pinning (exit 8) and agent revoke.
// Builds cmd/pastevault with Go, or uses PASTEVAULT_CLI_BIN.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { importFrontend } from '../scripts/lib/frontend-modules.mjs'
import { jsonRequest, projectRoot, request, runSuite, signUp } from './lib/harness.mjs'

function hasGo() {
  return spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0
}

if (!process.env.PASTEVAULT_CLI_BIN && !hasGo()) {
  if (process.env.CI) {
    console.error('e2e-agents: Go is required in CI (or set PASTEVAULT_CLI_BIN)')
    process.exit(1)
  }
  console.warn('e2e-agents: SKIPPED, no Go toolchain found (install Go or set PASTEVAULT_CLI_BIN)')
  process.exit(0)
}

function buildCli(directory) {
  if (process.env.PASTEVAULT_CLI_BIN) {
    return process.env.PASTEVAULT_CLI_BIN
  }

  const binary = path.join(directory, process.platform === 'win32' ? 'pastevault.exe' : 'pastevault')
  const result = spawnSync('go', ['build', '-o', binary, './cmd/pastevault'], {
    cwd: projectRoot,
    encoding: 'utf8',
    env: { ...process.env, CGO_ENABLED: '0' },
  })
  assert.equal(result.status, 0, `go build failed:\n${result.stderr}`)
  return binary
}

const CLI_ENVIRONMENT = [
  'PASTEVAULT_SERVER',
  'PASTEVAULT_PUBLIC_URL',
  'PASTEVAULT_TOKEN',
  'PASTEVAULT_PASSWORD',
  'PASTEVAULT_JSON',
  'PASTEVAULT_CONFIG_DIR',
  'PASTEVAULT_AGENT',
  'PASTEVAULT_AGENT_KEY',
]

const isPosix = process.platform !== 'win32'

await runSuite('agents', { postgres: true }, async ({ startServer, temporaryRoot, provider }) => {
  const binary = buildCli(temporaryRoot)
  const server = await startServer({ label: 'agents' })
  const { baseUrl, database } = server
  const { agentFingerprint } = await importFrontend('lib/fingerprint.ts')
  let configCounter = 0

  function newConfigDir(auth) {
    const directory = path.join(temporaryRoot, `config-${configCounter++}`)
    mkdirSync(directory, { recursive: true })
    if (auth) {
      writeFileSync(path.join(directory, 'auth.json'), JSON.stringify({ servers: { [baseUrl]: auth } }))
    }
    return directory
  }

  function cli(args, { input = '', config, env = {}, cwd = temporaryRoot } = {}) {
    const environment = { ...process.env }
    for (const name of CLI_ENVIRONMENT) {
      delete environment[name]
    }
    const result = spawnSync(binary, args, {
      cwd,
      input,
      encoding: 'utf8',
      env: {
        ...environment,
        PASTEVAULT_SERVER: baseUrl,
        PASTEVAULT_CONFIG_DIR: config ?? newConfigDir(),
        PASTEVAULT_NO_UPDATE_CHECK: '1',
        ...env,
      },
      timeout: 60_000,
    })
    return { status: result.status, stdout: result.stdout, stderr: result.stderr }
  }

  function json(result) {
    try {
      return JSON.parse(result.stdout)
    } catch {
      assert.fail(`stdout is not one JSON object (exit ${result.status}):\n${result.stdout}\n${result.stderr}`)
    }
  }

  function expectExit(result, status, label) {
    assert.equal(result.status, status, `${label}: exit ${result.status}, want ${status}\n${result.stdout}\n${result.stderr}`)
  }

  function cliJson(args, options, label = args.join(' ')) {
    const result = cli([...args, '--json'], options)
    expectExit(result, 0, label)
    return json(result)
  }

  async function viewCount(table, slug) {
    const [row] = await database.query(`SELECT "view_count" FROM "${table}" WHERE "slug" = $1`, slug)
    return Number(row.view_count)
  }

  async function auditEvents(headers, event) {
    const { response, body } = await request(baseUrl, `/api/account/audit?event=${event}&limit=200`, { headers })
    assert.equal(response.status, 200)
    return body.events
  }

  const owner = await signUp(baseUrl, 'agents')
  const configA = newConfigDir({ access_token: owner.sessionToken })
  const configB = newConfigDir({ access_token: owner.sessionToken })
  const anonymousConfig = newConfigDir()

  // ── capabilities ────────────────────────────────────────────────────
  {
    const { body } = await request(baseUrl, '/api/capabilities')
    assert.equal(body.features.agents, true)
    assert.equal(body.features.sealed_shares, true)
  }

  // ── agent init on two machines of one account ──────────────────────
  const alpha = cliJson(['agent', 'init', '--name', 'alpha'], { config: configA }).agent
  const beta = cliJson(['agent', 'init', '--name', 'beta'], { config: configB }).agent
  {
    for (const [agent, config] of [[alpha, configA], [beta, configB]]) {
      assert.match(agent.fingerprint, /^pvk1_[a-z2-7]{32}$/)
      assert.equal(agent.fingerprint, agentFingerprint(Buffer.from(agent.public_key, 'base64url')))
      assert.equal(agent.default, true)
      assert.equal(agent.pin, 'self')
      const keyFile = JSON.parse(readFileSync(agent.key_file, 'utf8'))
      assert.equal(keyFile.v, 1)
      assert.equal(keyFile.agent_id, agent.id)
      assert.equal(keyFile.public_key, agent.public_key)
      assert.match(keyFile.private_key, /^[A-Za-z0-9_-]{43}$/)
      if (isPosix) {
        assert.equal(statSync(agent.key_file).mode & 0o777, 0o600, 'agent key file is 0600')
        assert.equal(statSync(path.dirname(agent.key_file)).mode & 0o777, 0o700, 'agent key dir is 0700')
        assert.equal(statSync(path.join(config, 'agents')).mode & 0o777, 0o700)
        assert.equal(statSync(path.join(config, 'known_agents.json')).mode & 0o777, 0o600)
      }
      const pins = JSON.parse(readFileSync(path.join(config, 'known_agents.json'), 'utf8'))
      assert.equal(pins.servers[baseUrl][agent.name].source, 'self')
    }

    // A second init for the same name needs --force.
    expectExit(cli(['agent', 'init', '--name', 'alpha'], { config: configA }), 13, 'agent init again')

    const listed = cliJson(['agent', 'list'], { config: configA }).agents
    assert.deepEqual(listed.map((agent) => agent.name), ['alpha', 'beta'])
    assert.equal(listed.find((agent) => agent.name === 'alpha').local_key, true)
    assert.equal(listed.find((agent) => agent.name === 'beta').local_key, false)
    assert.equal(listed.find((agent) => agent.name === 'beta').pin, 'none')

    const shown = cliJson(['agent', 'show'], { config: configB })
    assert.equal(shown.agent.name, 'beta')
    assert.equal(shown.server_status, 'active')
    const pubkey = cliJson(['agent', 'pubkey'], { config: configB })
    assert.equal(pubkey.public_key, beta.public_key)
    const audit = await auditEvents(owner.headers, 'agent.registered')
    assert.equal(audit.length, 2)
  }

  // ── agents API rules ────────────────────────────────────────────────
  {
    const fresh = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x
    const freshFingerprint = agentFingerprint(Buffer.from(fresh, 'base64url'))

    const wrongFingerprint = await jsonRequest(baseUrl, '/api/agents', { name: 'gamma', public_key: fresh, fingerprint: beta.fingerprint }, owner.headers)
    assert.equal(wrongFingerprint.response.status, 400)
    assert.equal(wrongFingerprint.body.code, 'fingerprint_mismatch')

    const lowOrder = Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex')
    const lowOrderResult = await jsonRequest(baseUrl, '/api/agents', { name: 'gamma', public_key: lowOrder.toString('base64url'), fingerprint: agentFingerprint(lowOrder) }, owner.headers)
    assert.equal(lowOrderResult.response.status, 400)
    assert.equal(lowOrderResult.body.code, 'invalid_public_key')

    const nameTaken = await jsonRequest(baseUrl, '/api/agents', { name: 'beta', public_key: fresh, fingerprint: freshFingerprint }, owner.headers)
    assert.equal(nameTaken.response.status, 409)
    assert.equal(nameTaken.body.code, 'agent_name_taken')

    const keyTaken = await jsonRequest(baseUrl, '/api/agents', { name: 'gamma', public_key: beta.public_key, fingerprint: beta.fingerprint }, owner.headers)
    assert.equal(keyTaken.response.status, 409)
    assert.equal(keyTaken.body.code, 'public_key_taken')

    // Default tokens lack agents:write.
    const readOnly = await jsonRequest(baseUrl, '/api/account/tokens', { name: 'reader' }, owner.headers)
    const readOnlyHeaders = { authorization: `Bearer ${readOnly.body.token}` }
    const forbidden = await jsonRequest(baseUrl, '/api/agents', { name: 'gamma', public_key: fresh, fingerprint: freshFingerprint }, readOnlyHeaders)
    assert.equal(forbidden.response.status, 403)
    assert.equal(forbidden.body.required, 'agents:write')
    const { response: listResponse, body: listBody } = await request(baseUrl, '/api/agents', { headers: readOnlyHeaders })
    assert.equal(listResponse.status, 200)
    assert.equal(listBody.agents.length, 2)

    // A token that registers an agent becomes bound to it, once.
    const writer = await jsonRequest(baseUrl, '/api/account/tokens', { name: 'registrar', scopes: ['agents:write', 'agents:read', 'shares:receive'] }, owner.headers)
    const writerHeaders = { authorization: `Bearer ${writer.body.token}` }
    const registered = await jsonRequest(baseUrl, '/api/agents', { name: 'gamma', public_key: fresh, fingerprint: freshFingerprint }, writerHeaders)
    assert.equal(registered.response.status, 201)
    assert.equal(registered.body.token_bound, true)
    const me = await request(baseUrl, '/api/me', { headers: writerHeaders })
    assert.equal(me.body.auth.agent.name, 'gamma')
    const other = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x
    const second = await jsonRequest(baseUrl, '/api/agents', { name: 'delta', public_key: other, fingerprint: agentFingerprint(Buffer.from(other, 'base64url')) }, writerHeaders)
    assert.equal(second.response.status, 409)
    assert.equal(second.body.code, 'token_already_bound')

    // A token bound to gamma manages gamma only: it can't revoke alpha.
    const crossRevoke = await request(baseUrl, `/api/agents/${alpha.id}`, { method: 'DELETE', headers: writerHeaders })
    assert.equal(crossRevoke.response.status, 403)
    assert.equal(crossRevoke.body.error, 'other_agent')
    const stillActive = await request(baseUrl, '/api/agents', { headers: owner.headers })
    assert(stillActive.body.agents.some((agent) => agent.id === alpha.id && !agent.revoked_at))

    // Non-canonical keys are refused: top bit set, and non-canonical base64url.
    const topBit = Buffer.from(other, 'base64url')
    topBit[31] |= 0x80
    const nonCanonical = await jsonRequest(baseUrl, '/api/agents', { name: 'epsilon', public_key: topBit.toString('base64url'), fingerprint: agentFingerprint(topBit) }, owner.headers)
    assert.equal(nonCanonical.response.status, 400)
    assert.equal(nonCanonical.body.code, 'invalid_public_key')
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    const paddingBits = other.slice(0, -1) + alphabet[alphabet.indexOf(other.at(-1)) + 1]
    const badEncoding = await jsonRequest(baseUrl, '/api/agents', { name: 'epsilon', public_key: paddingBits, fingerprint: agentFingerprint(Buffer.from(paddingBits, 'base64url')) }, owner.headers)
    assert.equal(badEncoding.response.status, 400)
    assert.equal(badEncoding.body.code, 'invalid_public_key')

    // Revoking the agent revokes the token bound to it.
    const revoked = await request(baseUrl, `/api/agents/${registered.body.agent.id}`, { method: 'DELETE', headers: owner.headers })
    assert.equal(revoked.response.status, 200)
    assert.equal(revoked.body.tokens_revoked, 1)
    assert.equal((await request(baseUrl, '/api/me', { headers: writerHeaders })).response.status, 401)
    const again = await request(baseUrl, `/api/agents/${registered.body.agent.id}`, { method: 'DELETE', headers: owner.headers })
    assert.equal(again.body.agent.revoked_at, revoked.body.agent.revoked_at, 'revoke is idempotent')
    const withRevoked = await request(baseUrl, '/api/agents?include_revoked=1', { headers: owner.headers })
    assert(withRevoked.body.agents.some((agent) => agent.name === 'gamma' && agent.revoked_at))

    // Sealing to an agent: the agent must be the creator's, with its fingerprint.
    const stranger = await signUp(baseUrl, 'stranger')
    const foreign = await jsonRequest(baseUrl, '/api/pastes', {
      ciphertext: 'AAAA', nonce: Buffer.alloc(24).toString('base64url'),
      recipient: { agent_id: beta.id, fingerprint: beta.fingerprint, wrapped_key: 'A'.repeat(140) },
    }, stranger.headers)
    assert.equal(foreign.response.status, 400)
    assert.equal(foreign.body.code, 'recipient_agent_unknown')
    const mismatched = await jsonRequest(baseUrl, '/api/pastes', {
      ciphertext: 'AAAA', nonce: Buffer.alloc(24).toString('base64url'),
      recipient: { agent_id: beta.id, fingerprint: alpha.fingerprint, wrapped_key: 'A'.repeat(140) },
    }, owner.headers)
    assert.equal(mismatched.response.status, 400)
    assert.equal(mismatched.body.code, 'recipient_fingerprint_mismatch')
    const anonymousAgent = await jsonRequest(baseUrl, '/api/pastes', {
      ciphertext: 'AAAA', nonce: Buffer.alloc(24).toString('base64url'),
      recipient: { agent_id: beta.id, fingerprint: beta.fingerprint, wrapped_key: 'A'.repeat(140) },
    })
    assert.equal(anonymousAgent.response.status, 401)
  }

  // ── put --to beta: sealed paste, recipient auth, A can't open it ────
  {
    const put = cli(['put', '-', '--to', 'beta', '--json'], { input: 'for beta only\n', config: configA })
    expectExit(put, 0, 'put --to beta')
    assert.match(put.stderr, /Pinned beta pvk1_/)
    const sealed = json(put)
    assert.equal(sealed.kind, 'paste')
    assert.match(sealed.url, new RegExp(`^${baseUrl}/p/[A-Za-z0-9_-]{12}$`), 'sealed links carry no #k=')
    assert.equal(sealed.key_in_url, false)
    assert.deepEqual(sealed.recipient, { name: 'beta', fingerprint: beta.fingerprint })
    assert.equal(sealed.max_views, 1)
    const expiresIn = new Date(sealed.expires_at).getTime() - Date.now()
    assert(Math.abs(expiresIn - 3_600_000) < 120_000, `--to defaults to 1h, got ${sealed.expires_at}`)

    const meta = await request(baseUrl, `/api/pastes/${sealed.slug}/meta`)
    assert.deepEqual(meta.body.recipient, { fingerprint: beta.fingerprint })
    assert.equal(meta.body.requires_recipient_auth, true)
    assert.equal(meta.body.views_remaining, 1)

    // A holds no key for beta: exit 7 before anything is consumed.
    const fromA = cli(['get', sealed.url, '--stdout', '--json'], { config: configA })
    expectExit(fromA, 7, 'A opens a share sealed to beta')
    assert.equal(json(fromA).error.code, 'sealed_share')
    assert.equal(await viewCount('Paste', sealed.slug), 0)

    // Without the recipient's account the consuming GET is refused, unburned.
    const anonymous = await request(baseUrl, `/api/pastes/${sealed.slug}`)
    assert.equal(anonymous.response.status, 403)
    assert.equal(anonymous.body.error, 'recipient_auth_required')
    const stranger = await signUp(baseUrl, 'outsider')
    const otherAccount = await request(baseUrl, `/api/pastes/${sealed.slug}`, { headers: stranger.headers })
    assert.equal(otherAccount.response.status, 403)
    const receiveless = await jsonRequest(baseUrl, '/api/account/tokens', { name: 'no-receive', scopes: ['shares:read'] }, owner.headers)
    const noScope = await request(baseUrl, `/api/pastes/${sealed.slug}`, { headers: { authorization: `Bearer ${receiveless.body.token}` } })
    assert.equal(noScope.response.status, 403)
    assert.equal(await viewCount('Paste', sealed.slug), 0)
    const denied = await auditEvents(owner.headers, 'share.access_denied')
    const deniedForSlug = denied.filter((event) => event.slug === sealed.slug)
    // Different reasons are never folded into one event.
    assert(deniedForSlug.some((event) => event.actor_kind === 'anonymous' && event.details.reason === 'anonymous'))
    assert(deniedForSlug.some((event) => event.actor_kind === 'anonymous' && event.details.reason === 'other_account'))
    assert(deniedForSlug.some((event) => event.actor_kind === 'owner' && event.details.reason === 'missing_scope'))

    // An anonymous reader without credentials gets exit 3 before consuming.
    const betaKeyFile = path.join(configB, 'agents')
    const anonymousWithKey = newConfigDir()
    mkdirSync(path.join(anonymousWithKey, 'agents'), { recursive: true })
    const serverDir = readdirSync(betaKeyFile)[0]
    mkdirSync(path.join(anonymousWithKey, 'agents', serverDir), { recursive: true })
    writeFileSync(
      path.join(anonymousWithKey, 'agents', serverDir, 'beta.json'),
      readFileSync(path.join(betaKeyFile, serverDir, 'beta.json')),
      { mode: 0o600 }
    )
    expectExit(cli(['get', sealed.url, '--stdout'], { config: anonymousWithKey }), 3, 'sealed share without credentials')
    assert.equal(await viewCount('Paste', sealed.slug), 0)

    // B holds the key and the account: it opens, and the paste burns.
    const opened = cli(['get', sealed.url, '--stdout', '--json'], { config: configB })
    expectExit(opened, 0, 'B opens the sealed paste')
    const openedBody = json(opened)
    assert.equal(openedBody.content, 'for beta only\n')
    assert.equal(openedBody.burned, true)
    assert.deepEqual(openedBody.recipient, { name: 'beta', fingerprint: beta.fingerprint })
    expectExit(cli(['get', sealed.url, '--stdout'], { config: configB }), 5, 'burned sealed paste')

    const viewed = (await auditEvents(owner.headers, 'share.viewed')).find((event) => event.slug === sealed.slug)
    assert.equal(viewed.actor_kind, 'recipient')
    assert.equal(viewed.actor_agent.name, 'beta')
    const betaListed = cliJson(['agent', 'list'], { config: configA }).agents.find((agent) => agent.name === 'beta')
    assert.equal(betaListed.pin, 'tofu')
    assert(betaListed.last_used_at, 'opening a share sealed to beta marks beta used')
  }

  // ── sealed file share, by fingerprint prefix ────────────────────────
  {
    const sourceDirectory = path.join(temporaryRoot, 'files')
    mkdirSync(sourceDirectory, { recursive: true })
    const filePath = path.join(sourceDirectory, 'report.txt')
    writeFileSync(filePath, 'quarterly numbers\n'.repeat(100))

    const prefix = beta.fingerprint.slice(0, 13)
    const shared = cliJson(['put', filePath, '--to', prefix, '--max-views', '2'], { config: configA })
    assert.equal(shared.kind, 'file_share')
    assert.match(shared.url, new RegExp(`^${baseUrl}/f/[A-Za-z0-9_-]+$`))
    assert.equal(shared.recipient.name, 'beta')
    assert.equal(shared.max_views, 2)

    const fromA = cli(['get', shared.url, '--out', path.join(temporaryRoot, 'out-a')], { config: configA })
    expectExit(fromA, 7, 'A opens a file share sealed to beta')
    assert.equal(await viewCount('FileShare', shared.slug), 0)
    const anonymous = await request(baseUrl, `/api/file-shares/${shared.slug}`)
    assert.equal(anonymous.response.status, 403)
    assert.equal(await viewCount('FileShare', shared.slug), 0)

    const outDirectory = path.join(temporaryRoot, 'out-b')
    mkdirSync(outDirectory)
    const opened = cliJson(['get', shared.url, '--out', outDirectory], { config: configB })
    assert.equal(opened.files[0].name, 'report.txt')
    assert.equal(readFileSync(path.join(outDirectory, 'report.txt'), 'utf8'), 'quarterly numbers\n'.repeat(100))
    assert.equal(await viewCount('FileShare', shared.slug), 1)

    // After that non-final view, chunks still need the recipient account.
    const chunkPath = `/api/file-shares/${shared.slug}/chunks/someFileId/0`
    const anonymousChunk = await request(baseUrl, chunkPath)
    assert.equal(anonymousChunk.response.status, 403)
    assert.equal(anonymousChunk.body.error, 'recipient_auth_required')
    const ownerChunk = await request(baseUrl, chunkPath, { headers: owner.headers })
    assert.notEqual(ownerChunk.response.status, 403, 'the recipient account passes recipient auth for chunks')
  }

  // ── a server that relabels a #k= link as sealed is refused ──────────
  {
    // A normal share from A, then the database is edited as a malicious
    // server would: content replaced and "sealed" to beta, whose key B holds.
    const normal = cliJson(['put', '-'], { input: 'the real content', config: configA })
    assert.equal(normal.key_in_url, true)
    const { encryptPaste } = await importFrontend('lib/crypto.ts')
    const { wrapKey, wrapContext } = await importFrontend('lib/wrap.ts')
    const forged = await encryptPaste({ title: '', body: 'forged by the server', render_mode: 'plain' }, normal.slug)
    const wrapped = wrapKey(forged.key, Buffer.from(beta.public_key, 'base64url'), wrapContext.paste(normal.slug))
    await database.query(
      'UPDATE "Paste" SET "ciphertext" = $1, "nonce" = $2, "recipient_fingerprint" = $3, "recipient_agent_id" = $4, "recipient_user_id" = $5, "wrapped_key" = $6 WHERE "slug" = $7',
      forged.ciphertext, forged.nonce, beta.fingerprint, beta.id, owner.user.id, wrapped, normal.slug
    )

    const tampered = cli(['get', normal.url, '--stdout', '--json'], { config: configB })
    expectExit(tampered, 7, 'get of a #k= link the server claims is sealed')
    assert.equal(json(tampered).error.code, 'sealed_share_conflict')
    assert(!tampered.stdout.includes('forged'))
    assert.equal(await viewCount('Paste', normal.slug), 0)
  }

  // ── --to-key: sealed to a raw public key, no recipient auth ─────────
  {
    const pubkey = cliJson(['agent', 'pubkey', 'beta'], { config: configB }).public_key
    const sealed = cliJson(['put', '-', '--to-key', pubkey], { input: 'raw key share', config: anonymousConfig })
    assert.equal(sealed.key_in_url, false)
    assert.deepEqual(sealed.recipient, { fingerprint: beta.fingerprint })
    const meta = await request(baseUrl, `/api/pastes/${sealed.slug}/meta`)
    assert.equal(meta.body.requires_recipient_auth, false)

    expectExit(cli(['get', sealed.url, '--stdout'], { config: configA }), 7, 'A opens a raw-key share')
    assert.equal(await viewCount('Paste', sealed.slug), 0)

    // PASTEVAULT_AGENT_KEY instead of a key file, with no account at all.
    const keyFile = JSON.parse(readFileSync(beta.key_file, 'utf8'))
    const opened = cli(['get', sealed.slug, '--stdout'], { config: newConfigDir(), env: { PASTEVAULT_AGENT_KEY: keyFile.private_key } })
    expectExit(opened, 0, 'get with PASTEVAULT_AGENT_KEY')
    assert.equal(opened.stdout, 'raw key share')
    assert(!opened.stdout.includes(keyFile.private_key) && !opened.stderr.includes(keyFile.private_key))

    // Flag misuse.
    expectExit(cli(['put', '-', '--to-key', 'AAAA'], { input: 'x', config: anonymousConfig }), 2, 'bad --to-key')
    expectExit(cli(['put', '-', '--to-key', pubkey, '--password-file', keyFile.private_key], { input: 'x', config: anonymousConfig }), 2, '--to-key with a password')
    expectExit(cli(['put', '-', '--to', 'beta', '--to-key', pubkey], { input: 'x', config: configA }), 2, '--to and --to-key')
    expectExit(cli(['put', '-', '--to', 'beta'], { input: 'x', config: anonymousConfig }), 3, '--to without an account')
    expectExit(cli(['put', '-', '--to', 'nobody'], { input: 'x', config: configA }), 4, '--to an unknown agent')
  }

  // ── agent-bound tokens ──────────────────────────────────────────────
  {
    const created = cliJson(['token', 'create', '--name', 'beta-bot', '--agent', 'beta'], { config: configA })
    assert.equal(created.agent_id, beta.id)
    const alphaToken = cliJson(['token', 'create', '--name', 'alpha-bot', '--agent', 'alpha'], { config: configA })

    // A token bound to alpha can't take views of shares sealed to beta.
    const sealed = cliJson(['put', '-', '--to', 'beta'], { input: 'beta again', config: configA })
    const keyOnly = newConfigDir()
    const betaKey = JSON.parse(readFileSync(beta.key_file, 'utf8')).private_key
    const wrongAgent = cli(['get', sealed.slug, '--stdout'], { config: keyOnly, env: { PASTEVAULT_TOKEN: alphaToken.token, PASTEVAULT_AGENT_KEY: betaKey } })
    expectExit(wrongAgent, 3, 'alpha-bound token on a share sealed to beta')
    assert.match(wrongAgent.stderr, /recipient/)
    assert.equal(await viewCount('Paste', sealed.slug), 0)
    const rightAgent = cli(['get', sealed.slug, '--stdout'], { config: keyOnly, env: { PASTEVAULT_TOKEN: created.token, PASTEVAULT_AGENT_KEY: betaKey } })
    expectExit(rightAgent, 0, 'beta-bound token')
    assert.equal(rightAgent.stdout, 'beta again')

    const whoami = cliJson(['whoami'], { config: keyOnly, env: { PASTEVAULT_TOKEN: created.token } })
    assert.equal(whoami.auth.agent.name, 'beta')

    // A share sealed before the revoke stays readable with the kept key.
    const beforeRevoke = cliJson(['put', '-', '--to', 'beta'], { input: 'sealed before revoke', config: configA })

    const revoked = cliJson(['agent', 'revoke', 'beta'], { config: configB })
    assert.equal(revoked.tokens_revoked, 1)
    assert.match(revoked.agent.key_file, /revoked[\\/]beta-\d+\.json$/)
    expectExit(cli(['whoami'], { config: keyOnly, env: { PASTEVAULT_TOKEN: created.token } }), 3, 'token of a revoked agent')
    const tokens = cliJson(['token', 'list'], { config: configA }).tokens
    assert(tokens.find((token) => token.name === 'beta-bot').revoked_at)

    const late = cli(['get', beforeRevoke.url, '--stdout'], { config: configB })
    expectExit(late, 0, 'open a share sealed before the revoke')
    assert.equal(late.stdout, 'sealed before revoke')
    expectExit(cli(['put', '-', '--to', 'beta'], { input: 'x', config: configA }), 4, '--to a revoked agent')

    // beta re-created on its machine: the name is free again.
    const reborn = cliJson(['agent', 'init', '--name', 'beta'], { config: configB }).agent
    assert.notEqual(reborn.fingerprint, beta.fingerprint)
    // A pinned the old key, so sealing to the new one needs agent trust.
    const mismatch = cli(['put', '-', '--to', 'beta', '--json'], { input: 'x', config: configA })
    expectExit(mismatch, 8, 'pinned key differs')
    assert.equal(json(mismatch).error.code, 'fingerprint_mismatch')
    assert.match(mismatch.stderr, /agent trust beta pvk1_/)
    cliJson(['agent', 'trust', 'beta', reborn.fingerprint], { config: configA })
    const trusted = cliJson(['put', '-', '--to', 'beta'], { input: 'after trust', config: configA })
    const afterTrust = cli(['get', trusted.url, '--stdout'], { config: configB })
    expectExit(afterTrust, 0, 'open after trust')
    assert.equal(afterTrust.stdout, 'after trust')
    Object.assign(beta, reborn)
  }

  // ── a server that swaps beta's key: put --to beta exits 8 ───────────
  {
    const [row] = await database.query('SELECT "id", "public_key" FROM "AgentIdentity" WHERE "id" = $1', beta.id)
    const substitute = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x
    await database.query('UPDATE "AgentIdentity" SET "public_key" = $1 WHERE "id" = $2', substitute, beta.id)
    try {
      const before = (await request(baseUrl, '/api/account/shares', { headers: owner.headers })).body.shares.length
      const swapped = cli(['put', '-', '--to', 'beta', '--json'], { input: 'must not be sealed to the substitute', config: configA })
      expectExit(swapped, 8, 'put --to beta with a swapped key')
      assert.equal(json(swapped).error.code, 'fingerprint_mismatch')
      const after = (await request(baseUrl, '/api/account/shares', { headers: owner.headers })).body.shares.length
      assert.equal(after, before, 'nothing was shared')

      // agent list flags the server's stale fingerprint claim and the pin.
      const listed = cliJson(['agent', 'list'], { config: configA }).agents.find((agent) => agent.name === 'beta')
      assert.equal(listed.fingerprint_mismatch, true)
      assert.equal(listed.pin, 'mismatch')

      // And trust refuses a fingerprint the server's key doesn't have.
      expectExit(cli(['agent', 'trust', 'beta', beta.fingerprint], { config: configA }), 8, 'trust a fingerprint the server key lacks')
      // On beta's own machine the local key wins too.
      expectExit(cli(['put', '-', '--to', 'beta'], { input: 'x', config: configB }), 8, 'own key swapped on the server')
    } finally {
      await database.query('UPDATE "AgentIdentity" SET "public_key" = $1 WHERE "id" = $2', row.public_key, beta.id)
    }
    cliJson(['put', '-', '--to', 'beta'], { input: 'restored', config: configA })
  }

  console.log(`E2E agents test passed (${provider}): agent init, sealed pastes and files, recipient auth, pins, revoke`)
})
