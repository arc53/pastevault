// The native Go CLI against a real server: pastes in the web's /p/ format,
// key and password sources, view limits, exit codes, API tokens and read
// receipts. Builds cmd/pastevault with Go, or uses PASTEVAULT_CLI_BIN.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { importFrontend } from '../scripts/lib/frontend-modules.mjs'
import { projectRoot, request, runSuite, signUp, sleep } from './lib/harness.mjs'

function findGo() {
  const result = spawnSync('go', ['version'], { encoding: 'utf8' })
  return result.status === 0
}

async function buildCli(directory) {
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

if (!process.env.PASTEVAULT_CLI_BIN && !findGo()) {
  if (process.env.CI) {
    console.error('e2e-cli: Go is required in CI (or set PASTEVAULT_CLI_BIN)')
    process.exit(1)
  }
  console.warn('e2e-cli: SKIPPED, no Go toolchain found (install Go or set PASTEVAULT_CLI_BIN)')
  process.exit(0)
}

// Variables the CLI reads; tests set them explicitly per call.
const CLI_ENVIRONMENT = [
  'PASTEVAULT_SERVER',
  'PASTEVAULT_PUBLIC_URL',
  'PASTEVAULT_TOKEN',
  'PASTEVAULT_PASSWORD',
  'PASTEVAULT_JSON',
  'PASTEVAULT_CONFIG_DIR',
]

await runSuite('cli', {}, async ({ startServer, temporaryRoot }) => {
  const binary = await buildCli(temporaryRoot)
  const server = await startServer({ label: 'cli' })
  const { baseUrl } = server
  const frontendCrypto = await importFrontend('lib/crypto.ts')
  let configCounter = 0

  function newConfigDir() {
    const directory = path.join(temporaryRoot, `config-${configCounter++}`)
    mkdirSync(directory, { recursive: true })
    return directory
  }

  const defaultConfig = newConfigDir()

  function environment(extra = {}) {
    const env = { ...process.env }
    for (const name of CLI_ENVIRONMENT) {
      delete env[name]
    }
    return {
      ...env,
      PASTEVAULT_SERVER: baseUrl,
      PASTEVAULT_CONFIG_DIR: defaultConfig,
      PASTEVAULT_NO_UPDATE_CHECK: '1',
      ...extra,
    }
  }

  function cli(args, { input = '', env = {}, cwd = temporaryRoot } = {}) {
    const result = spawnSync(binary, args, {
      cwd,
      input,
      encoding: 'utf8',
      env: environment(env),
      timeout: 60_000,
    })
    return { status: result.status, stdout: result.stdout, stderr: result.stderr }
  }

  function cliAsync(args, { env = {} } = {}) {
    return new Promise((resolve, reject) => {
      const child = spawn(binary, args, { cwd: temporaryRoot, env: environment(env), stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', (chunk) => (stdout += chunk))
      child.stderr.on('data', (chunk) => (stderr += chunk))
      child.once('error', reject)
      child.once('exit', (status) => resolve({ status, stdout, stderr }))
    })
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

  function putJson(args, options) {
    const result = cli(['put', ...args, '--json'], options)
    expectExit(result, 0, `put ${args.join(' ')}`)
    return json(result)
  }

  async function pasteMeta(slug) {
    return request(baseUrl, `/api/pastes/${slug}/meta`)
  }

  // ── stdin round trip ────────────────────────────────────────────────
  {
    const created = putJson(['-'], { input: 'hello from the CLI\n' })
    assert.equal(created.kind, 'paste')
    assert.match(created.url, new RegExp(`^${baseUrl}/p/[A-Za-z0-9_-]{12}#k=[A-Za-z0-9_-]{43}$`))
    assert.equal(created.key_in_url, true)
    assert.equal(created.recipient, null)
    assert.equal(created.max_views, null)
    const expiresIn = new Date(created.expires_at).getTime() - Date.now()
    assert(Math.abs(expiresIn - 24 * 3_600_000) < 120_000, `default expiry is 24h, got ${created.expires_at}`)

    const opened = cli(['get', created.url, '--stdout'])
    expectExit(opened, 0, 'get --stdout')
    assert.equal(opened.stdout, 'hello from the CLI\n')

    // No arguments with piped stdin is a paste too; -q prints only the URL.
    const quiet = cli(['put', '-q'], { input: 'piped without dash' })
    expectExit(quiet, 0, 'put -q')
    assert.equal(quiet.stdout.trim().split('\n').length, 1)
    const reopened = cli(['get', quiet.stdout.trim(), '--stdout'])
    assert.equal(reopened.stdout, 'piped without dash')
  }

  // ── .env file → paste the web can read ─────────────────────────────
  {
    const envDirectory = path.join(temporaryRoot, 'project')
    mkdirSync(envDirectory, { recursive: true })
    const envBody = 'API_KEY=sk-test-123\nDATABASE_URL="postgres://u:p@db/app"\n'
    writeFileSync(path.join(envDirectory, '.env'), envBody)

    const created = putJson(['.env', '--expires', '15m'], { cwd: envDirectory })
    assert.equal(created.kind, 'paste')
    const expiresIn = new Date(created.expires_at).getTime() - Date.now()
    assert(Math.abs(expiresIn - 15 * 60_000) < 60_000, `--expires 15m, got ${created.expires_at}`)

    // Decrypt with the web app's own code, as the /p/ page does.
    const slug = created.slug
    const key = frontendCrypto.base64urlDecode(new URL(created.url).hash.replace('#k=', ''))
    const fetched = await request(baseUrl, `/api/pastes/${slug}`)
    assert.equal(fetched.response.status, 200)
    const content = await frontendCrypto.decryptPaste(fetched.body.ciphertext, fetched.body.nonce, key, slug)
    assert.deepEqual(content, { title: '.env', body: envBody, render_mode: 'plain', language_hint: 'bash' })

    // get --out writes the paste under its title, mode 0600.
    const outDirectory = path.join(temporaryRoot, 'restored')
    const restored = cli(['get', created.url, '--out', outDirectory, '--json'])
    expectExit(restored, 0, 'get --out')
    const restoredJson = json(restored)
    assert.equal(restoredJson.written_to, path.join(outDirectory, '.env'))
    assert.equal(restoredJson.content, undefined, 'content is only in JSON with --stdout')
    assert.equal(readFileSync(path.join(outDirectory, '.env'), 'utf8'), envBody)
    if (process.platform !== 'win32') {
      assert.equal(statSync(path.join(outDirectory, '.env')).mode & 0o777, 0o600)
    }
  }

  // ── password mode, readable by the web ─────────────────────────────
  {
    const created = putJson(['-', '--password', '--title', 'locked', '--format', 'markdown'], {
      input: '# Locked note\n',
      env: { PASTEVAULT_PASSWORD: 'open sesame' },
    })
    assert.equal(created.password_protected, true)
    assert.equal(created.key_in_url, false)
    assert(!created.url.includes('#'))

    const meta = await pasteMeta(created.slug)
    assert.equal(meta.body.password_protected, true)
    const fetched = await request(baseUrl, `/api/pastes/${created.slug}`)
    const content = await frontendCrypto.decryptPasteWithPassword(
      fetched.body.ciphertext,
      fetched.body.nonce,
      fetched.body.salt,
      fetched.body.kdf_params,
      'open sesame',
      created.slug
    )
    assert.deepEqual(content, { title: 'locked', body: '# Locked note\n', render_mode: 'markdown' })

    const passwordFile = path.join(temporaryRoot, 'password.txt')
    writeFileSync(passwordFile, 'open sesame\n')
    const missing = cli(['get', created.slug, '--stdout'])
    expectExit(missing, 2, 'password-protected without a password')
    const wrong = cli(['get', created.slug, '--stdout'], { env: { PASTEVAULT_PASSWORD: 'nope' } })
    expectExit(wrong, 7, 'wrong password')
    const right = cli(['get', created.slug, '--stdout', '--password-file', passwordFile])
    expectExit(right, 0, 'right password')
    assert.equal(right.stdout, '# Locked note\n')
  }

  // ── --no-key-in-output + --key-file ────────────────────────────────
  {
    const keyFile = path.join(temporaryRoot, 'share.key')
    const created = putJson(['-', '--no-key-in-output', '--key-out', keyFile], { input: 'keyed' })
    assert.equal(created.key_in_url, false)
    assert(!created.url.includes('#'), 'the URL must not carry the key')
    assert.equal(created.key_file, keyFile)
    if (process.platform !== 'win32') {
      assert.equal(statSync(keyFile).mode & 0o777, 0o600)
    }

    const noKey = cli(['get', created.url, '--stdout'])
    expectExit(noKey, 2, 'get without the key')
    assert.equal((await pasteMeta(created.slug)).response.status, 200, 'a failed get must not consume')

    const withKey = cli(['get', created.url, '--key-file', keyFile, '--stdout'])
    expectExit(withKey, 0, 'get --key-file')
    assert.equal(withKey.stdout, 'keyed')

    const viaStdin = cli(['get', `pv://share/${created.slug}`, '--key-stdin', '--stdout'], {
      input: readFileSync(keyFile, 'utf8'),
    })
    expectExit(viaStdin, 0, 'get pv://share --key-stdin')
    assert.equal(viaStdin.stdout, 'keyed')
  }

  // ── view limits and gone/missing exit codes ────────────────────────
  {
    const twice = putJson(['-', '--max-views', '2'], { input: 'two views' })
    assert.equal(twice.max_views, 2)
    for (const view of [1, 2]) {
      const opened = cli(['get', twice.url, '--json', '--stdout'])
      expectExit(opened, 0, `view ${view}`)
      const body = json(opened)
      assert.equal(body.content, 'two views')
      assert.equal(body.view_count, view)
      assert.equal(body.views_remaining, 2 - view)
    }
    const third = cli(['get', twice.url, '--json', '--stdout'])
    expectExit(third, 5, 'third view of max-views 2')
    assert.equal(json(third).error.code, 'gone')
    assert.equal(json(third).error.exit_code, 5)

    const burn = putJson(['-', '--burn'], { input: 'once' })
    assert.equal(burn.max_views, 1)
    assert.equal(burn.burn_after_read, true)
    expectExit(cli(['get', burn.url, '--stdout']), 0, 'burn first view')
    expectExit(cli(['get', burn.url, '--stdout']), 5, 'burned share')

    const missing = cli(['get', 'doesNotExist1', '--json'])
    expectExit(missing, 4, 'missing share')
    assert.equal(json(missing).error.code, 'not_found')
  }

  // ── accounts: session, API tokens, list, status, audit, revoke ─────
  {
    const owner = await signUp(baseUrl, 'cli')
    const sessionConfig = newConfigDir()
    writeFileSync(
      path.join(sessionConfig, 'auth.json'),
      JSON.stringify({ servers: { [baseUrl]: { access_token: owner.sessionToken } } })
    )
    const asSession = { env: { PASTEVAULT_CONFIG_DIR: sessionConfig } }

    const whoami = cli(['whoami', '--json'], asSession)
    expectExit(whoami, 0, 'whoami (session)')
    assert.equal(json(whoami).auth.kind, 'session')

    // Token management is session-only.
    const created = cli(['token', 'create', '--name', 'ci', '--expires', '30d', '--json'], asSession)
    expectExit(created, 0, 'token create')
    const token = json(created)
    assert.match(token.token, /^pv_pat_[a-z2-7]{52}$/)
    assert(!token.scopes.includes('agents:write'))

    const plainCreate = cli(['token', 'create', '--name', 'plain', '-q'], asSession)
    expectExit(plainCreate, 0, 'token create -q')
    assert.match(plainCreate.stdout.trim(), /^pv_pat_[a-z2-7]{52}$/)

    const listed = json(cli(['token', 'list', '--json'], asSession))
    assert.deepEqual(listed.tokens.map((entry) => entry.name).sort(), ['ci', 'plain'])
    assert(!JSON.stringify(listed).includes(token.token), 'token list never shows tokens')

    const tokenOnly = { env: { PASTEVAULT_TOKEN: token.token, PASTEVAULT_CONFIG_DIR: newConfigDir() } }
    expectExit(cli(['token', 'list'], tokenOnly), 3, 'token list with only an API token')

    // PASTEVAULT_TOKEN: put is owned, then shows up in list.
    const owned = putJson(['-', '--max-views', '3'], { input: 'owned by token', ...tokenOnly })
    const shares = json(cli(['list', '--json'], tokenOnly))
    const share = shares.shares.find((entry) => entry.slug === owned.slug)
    assert(share, 'the token-created share is listed')
    assert.equal(share.max_views, 3)
    assert.equal(share.share_type, 'paste')
    const whoamiToken = json(cli(['whoami', '--json'], tokenOnly))
    assert.equal(whoamiToken.auth.kind, 'token')
    assert.equal(whoamiToken.auth.source, 'env_token')

    // login --with-token reads stdin and stores the token.
    const storedConfig = newConfigDir()
    const login = cli(['login', '--with-token'], { input: `${token.token}\n`, env: { PASTEVAULT_CONFIG_DIR: storedConfig } })
    expectExit(login, 0, 'login --with-token')
    assert(!login.stdout.includes(token.token) && !login.stderr.includes(token.token))
    const storedAuth = JSON.parse(readFileSync(path.join(storedConfig, 'auth.json'), 'utf8'))
    assert.equal(storedAuth.servers[baseUrl].token, token.token)
    const storedWhoami = json(cli(['whoami', '--json'], { env: { PASTEVAULT_CONFIG_DIR: storedConfig } }))
    assert.equal(storedWhoami.auth.source, 'stored_token')
    expectExit(cli(['login', '--with-token'], { input: 'not-a-token\n', env: { PASTEVAULT_CONFIG_DIR: newConfigDir() } }), 2, 'bad token')

    // status --wait viewed is a read receipt.
    const receipt = putJson(['-'], { input: 'read me', ...asSession })
    const notYet = cli(['status', receipt.slug, '--wait', 'viewed', '--timeout', '1s', '--interval', '200ms', '--json'], asSession)
    expectExit(notYet, 9, 'status --wait timeout')
    assert.equal(json(notYet).error.code, 'timeout')

    const waiting = cliAsync(['status', receipt.url, '--wait', 'viewed', '--timeout', '30s', '--interval', '250ms', '--json'], asSession)
    await sleep(750)
    expectExit(cli(['get', receipt.url, '--stdout']), 0, 'view for the receipt')
    const waited = await waiting
    expectExit(waited, 0, 'status --wait viewed')
    const status = json(waited)
    assert.equal(status.view_count, 1)
    assert.equal(status.waited_for, 'viewed')
    assert.deepEqual(status.events.map((event) => event.event), ['share.created', 'share.viewed'])

    const audit = json(cli(['audit', '--since', '1h', '--json'], tokenOnly))
    const auditEvents = audit.events.map((event) => event.event)
    for (const expected of ['token.created', 'share.created', 'share.viewed']) {
      assert(auditEvents.includes(expected), `audit includes ${expected}`)
    }
    assert(audit.events.some((event) => event.client?.startsWith('pastevault-cli/')))

    // revoke deletes the share; it is then missing.
    const revoked = cli(['revoke', owned.url, '--json'], tokenOnly)
    expectExit(revoked, 0, 'revoke')
    assert.equal(json(revoked).revoked[0].status, 'deleted')
    expectExit(cli(['get', owned.url, '--stdout']), 4, 'get after revoke')
    expectExit(cli(['revoke', 'nosuchshare'], tokenOnly), 4, 'revoke unknown share')

    // token revoke by prefix; the token then stops working (exit 3).
    const revokeToken = cli(['token', 'revoke', token.prefix, '--json'], asSession)
    expectExit(revokeToken, 0, 'token revoke')
    assert(json(revokeToken).token.revoked_at)
    const afterRevoke = cli(['put', '-', '--json'], { input: 'x', ...tokenOnly })
    expectExit(afterRevoke, 3, 'put with a revoked token')
    assert.equal(json(afterRevoke).error.code, 'auth')

    // logout removes the stored session.
    const logout = cli(['logout', '--json'], asSession)
    expectExit(logout, 0, 'logout')
    assert.equal(json(logout).removed_session, true)
    expectExit(cli(['token', 'list'], asSession), 3, 'token list after logout')
  }

  // ── usage errors ───────────────────────────────────────────────────
  {
    const bad = cli(['put', '--expires', '3w', '--json'], { input: 'x' })
    expectExit(bad, 2, 'bad --expires')
    assert.equal(json(bad).error.code, 'usage')
    expectExit(cli(['put', '--burn', '--max-views', '3'], { input: 'x' }), 2, '--burn with --max-views 3')
  }

  console.log('CLI e2e checks passed')
})
