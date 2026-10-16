// Secret requests, the local store, run and inject end to end: the Go CLI's
// request/await/fulfil/decline/cancel, secret, get --save, run (masking, env
// stripping, exit codes) and inject against a real server, plus the
// secret-request API rules (session-only answers, other accounts, slow_down,
// the delivery lease, ack, limits) and what the database holds.
// Builds cmd/pastevault with Go, or uses PASTEVAULT_CLI_BIN.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { importFrontend } from '../scripts/lib/frontend-modules.mjs'
import { jsonRequest, projectRoot, request, runSuite, signUp, sleep } from './lib/harness.mjs'

function hasGo() {
  return spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0
}

if (!process.env.PASTEVAULT_CLI_BIN && !hasGo()) {
  if (process.env.CI) {
    console.error('e2e-requests: Go is required in CI (or set PASTEVAULT_CLI_BIN)')
    process.exit(1)
  }
  console.warn('e2e-requests: SKIPPED, no Go toolchain found (install Go or set PASTEVAULT_CLI_BIN)')
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
const b64 = (value) => Buffer.from(value).toString('base64')

await runSuite('requests', { postgres: true }, async ({ startServer, temporaryRoot, provider }) => {
  const binary = buildCli(temporaryRoot)
  const server = await startServer({
    label: 'requests',
    environment: { SECRET_REQUEST_MIN_TTL_SECONDS: '5' },
  })
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

  function cliEnvironment(config, env) {
    const environment = { ...process.env }
    for (const name of CLI_ENVIRONMENT) {
      delete environment[name]
    }
    return {
      ...environment,
      PASTEVAULT_SERVER: baseUrl,
      PASTEVAULT_CONFIG_DIR: config ?? newConfigDir(),
      PASTEVAULT_NO_UPDATE_CHECK: '1',
      ...env,
    }
  }

  function cli(args, { input = '', config, env = {}, cwd = temporaryRoot } = {}) {
    const result = spawnSync(binary, args, {
      cwd,
      input,
      encoding: 'utf8',
      env: cliEnvironment(config, env),
      timeout: 90_000,
    })
    return { status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr }
  }

  function cliAsync(args, { config, env = {} } = {}) {
    const child = spawn(binary, args, { cwd: temporaryRoot, env: cliEnvironment(config, env) })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => (stdout += chunk))
    child.stderr.on('data', (chunk) => (stderr += chunk))
    const done = new Promise((resolve) =>
      child.on('exit', (status, signal) => resolve({ status, signal, stdout, stderr }))
    )
    return { child, done, stdout: () => stdout }
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

  async function requestRow(id) {
    const [row] = await database.query('SELECT * FROM "SecretRequest" WHERE "id" = $1', id)
    return row
  }

  function requestFile(config, id) {
    return path.join(config, 'requests', `${id}.json`)
  }

  function assertPrivate(file, mode = 0o600) {
    if (isPosix) {
      assert.equal(statSync(file).mode & 0o777, mode, `${file} mode`)
    }
  }

  // ── accounts, agent, credentials ─────────────────────────────────────
  const owner = await signUp(baseUrl, 'requests')
  const other = await signUp(baseUrl, 'outsider')
  // The agent's machine: its key file, and an API token bound to it.
  const agentConfig = newConfigDir({ access_token: owner.sessionToken })
  // The human's machine: only the login session.
  const humanConfig = newConfigDir({ access_token: owner.sessionToken })
  const outsiderConfig = newConfigDir({ access_token: other.sessionToken })

  {
    const { body } = await request(baseUrl, '/api/capabilities')
    assert.equal(body.features.secret_requests, true)
    assert.equal(body.limits.min_secret_request_ttl_seconds, 5)
    assert(body.limits.max_secret_request_bytes > 0)
  }

  const agent = cliJson(['agent', 'init', '--name', 'builder'], { config: agentConfig }).agent
  const agentToken = cliJson(['token', 'create', '--name', 'builder-bot', '--agent', 'builder'], {
    config: agentConfig,
  }).token
  assert.match(agentToken, /^pv_pat_/)
  const asAgent = { config: agentConfig, env: { PASTEVAULT_TOKEN: agentToken } }

  // ── request → fulfil (CLI session) → await → pv://secret ────────────
  const secretValue = 'sk-test-' + 'Zq9'.repeat(10) + '-end'
  let first
  {
    first = cliJson(['request', 'OPENAI_API_KEY', '--why', 'run the evals\nnow'], asAgent)
    assert.equal(first.status, 'pending')
    assert.match(first.code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/)
    assert.equal(first.url, `${baseUrl}/r/${first.code}#fp=${first.fingerprint}`)
    assert.equal(first.agent, 'builder')
    assert.notEqual(first.fingerprint, agent.fingerprint, 'requests use their own ephemeral key')

    // The request file holds the poll token and ephemeral key, 0600.
    const file = requestFile(agentConfig, first.id)
    assertPrivate(file)
    assertPrivate(path.dirname(file), 0o700)
    const pending = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(pending.fingerprint, first.fingerprint)
    assert(pending.poll_token && pending.private_key)

    // The page data (session of the same account): key matches #fp.
    const { response, body } = await request(baseUrl, `/api/secret-requests/by-code/${first.code.toLowerCase()}`, {
      headers: owner.headers,
    })
    assert.equal(response.status, 200)
    assert.equal(body.id, first.id)
    assert.equal(body.name, 'OPENAI_API_KEY')
    assert.equal(body.reason, 'run the evals\nnow')
    assert.equal(body.accept, 'text')
    assert.equal(agentFingerprint(Buffer.from(body.public_key, 'base64url')), first.fingerprint)
    assert.equal(body.requester.agent.name, 'builder')
    assert.equal(body.requester.agent.fingerprint, agent.fingerprint)
    assert.equal(body.requester.token_name, 'builder-bot')
    assert.equal(body.status, 'pending')
    assert(body.max_bytes > 0)
    assert(body.opened_at)

    // fulfil checks the key against the URL's #fp before sending anything.
    const tampered = first.url.replace(/#fp=.*/, `#fp=${agent.fingerprint}`)
    expectExit(cli(['request', 'fulfil', tampered, '--from-stdin'], { config: humanConfig, input: secretValue }), 8, 'fulfil with wrong #fp')
    expectExit(cli(['request', 'fulfil', first.code, '--from-stdin'], { config: humanConfig, input: secretValue }), 2, 'fulfil without fingerprint')
    // An API token can't answer (fulfil is session-only).
    expectExit(
      cli(['request', 'fulfil', first.url, '--from-stdin'], {
        config: newConfigDir(),
        env: { PASTEVAULT_TOKEN: agentToken },
        input: secretValue,
      }),
      3,
      'fulfil without a session'
    )

    const fulfilled = cli(['request', 'fulfil', first.url, '--from-stdin', '--json'], {
      config: humanConfig,
      input: secretValue + '\n',
    })
    expectExit(fulfilled, 0, 'fulfil')
    assert.equal(json(fulfilled).status, 'fulfilled')
    // The untrusted reason is printed quoted, as data.
    assert.match(fulfilled.stderr, /"run the evals\\nnow"/)

    // The server holds ciphertext only.
    const row = await requestRow(first.id)
    assert.equal(row.status, 'fulfilled')
    assert(row.response_ciphertext && row.response_wrapped_key && row.response_nonce)
    const serialized = JSON.stringify(row)
    for (const leak of [secretValue, b64(secretValue), Buffer.from(secretValue).toString('base64url'), Buffer.from(secretValue).toString('hex')]) {
      assert(!serialized.includes(leak), 'the database row must not contain the secret')
    }
    assert.notEqual(row.poll_token_hash, pending.poll_token)
    assert(!serialized.includes(pending.poll_token))

    const awaited = cliJson(['await', first.code], asAgent)
    assert.equal(awaited.status, 'delivered')
    assert.equal(awaited.handle, 'pv://secret/OPENAI_API_KEY')
    assert(!existsSync(file), 'the request file (ephemeral key) is deleted after the ack')

    const store = path.join(agentConfig, 'store')
    const [serverDir] = readdirSync(store)
    const entryFile = path.join(store, serverDir, 'builder', 'OPENAI_API_KEY.pvs')
    assertPrivate(entryFile)
    assertPrivate(path.dirname(entryFile), 0o700)
    const entry = JSON.parse(readFileSync(entryFile, 'utf8'))
    assert.equal(entry.kind, 'text')
    assert.equal(entry.source.type, 'request')
    assert.equal(entry.fingerprint, agent.fingerprint)
    assert(!readFileSync(entryFile, 'utf8').includes(secretValue))

    // Acked: the response is wiped server-side.
    const acked = await requestRow(first.id)
    assert.equal(acked.status, 'delivered')
    assert.equal(acked.response_ciphertext, null)
    assert.equal(acked.response_wrapped_key, null)
    assert(acked.acked_at && acked.delivered_at)

    // Audit trail.
    const { body: audit } = await request(baseUrl, `/api/account/audit?limit=200`, { headers: owner.headers })
    const events = audit.events.filter((event) => event.subject_id === first.id).map((event) => event.event)
    for (const name of ['request.created', 'request.opened', 'request.fulfilled', 'request.delivered']) {
      assert(events.includes(name), `audit has ${name}`)
    }
    assert(!JSON.stringify(audit).includes(secretValue))
  }

  // ── secret list / reveal / import ───────────────────────────────────
  {
    const listed = cliJson(['secret', 'list'], { config: agentConfig })
    assert.equal(listed.agent, 'builder')
    assert.deepEqual(
      listed.secrets.map((entry) => [entry.name, entry.handle, entry.kind]),
      [['OPENAI_API_KEY', 'pv://secret/OPENAI_API_KEY', 'text']]
    )
    assert(!JSON.stringify(listed).includes(secretValue))
    // reveal needs a terminal.
    expectExit(cli(['secret', 'reveal', 'OPENAI_API_KEY'], { config: agentConfig }), 2, 'reveal without a terminal')

    const imported = cliJson(['secret', 'import', 'DB_URL', '--from-stdin'], {
      config: agentConfig,
      input: 'postgres://u:Secr3tPassw0rd@db/x\n',
    })
    assert.equal(imported.handle, 'pv://secret/DB_URL')
    expectExit(cli(['secret', 'import', 'DB_URL', '--from-stdin'], { config: agentConfig, input: 'x' }), 13, 'import over an existing secret')
  }

  // ── run: resolution, masking, env stripping, exit codes ─────────────
  if (isPosix) {
    const envFile = path.join(temporaryRoot, '.env.pv')
    writeFileSync(
      envFile,
      [
        '# handles resolve, other values pass through',
        'X=pv://secret/OPENAI_API_KEY',
        'export DATABASE_URL="pv://secret/DB_URL"',
        "PLAIN='hello world'",
      ].join('\n')
    )

    const run = cli(
      [
        'run',
        '--env-file',
        envFile,
        '--',
        'sh',
        '-c',
        'echo "$X"; echo "$X" | base64; printf %s "$X" | base64; printf %s "$X" | od -An -tx1 | tr -d " \\n"; echo; echo "$DATABASE_URL"; echo "$PLAIN"; echo "tok=${PASTEVAULT_TOKEN:-unset}"; echo "err $X" >&2',
      ],
      asAgent
    )
    expectExit(run, 0, 'run')
    const combined = run.stdout + run.stderr
    for (const leak of [secretValue, b64(secretValue + '\n'), b64(secretValue), 'Secr3tPassw0rd']) {
      assert(!combined.includes(leak), `run output leaks ${leak.slice(0, 12)}…:\n${combined}`)
    }
    const lines = run.stdout.split('\n')
    assert.equal(lines[0], '[masked:X]')
    assert.match(lines[1], /^\[masked:X\]/)
    assert.match(lines[2], /^\[masked:X\]/)
    assert.equal(lines[4], '[masked:DATABASE_URL]')
    assert.equal(lines[5], 'hello world')
    assert.equal(lines[6], 'tok=unset', 'PASTEVAULT_TOKEN is stripped from the child')
    assert.match(run.stderr, /err \[masked:X\]/)

    // --no-mask passes values through (opt-out).
    const unmasked = cli(['run', '--env-file', envFile, '--no-mask', '--', 'sh', '-c', 'echo "$X"'], asAgent)
    expectExit(unmasked, 0, 'run --no-mask')
    assert.equal(unmasked.stdout, `${secretValue}\n`)

    // pv:// values in the inherited environment resolve too; the agent key
    // and password never reach the child.
    const inherited = cli(['run', '--', 'sh', '-c', 'echo "$Y"; echo "k=${PASTEVAULT_AGENT_KEY:-unset} p=${PASTEVAULT_PASSWORD:-unset}"'], {
      ...asAgent,
      env: { ...asAgent.env, Y: 'pv://secret/OPENAI_API_KEY', PASTEVAULT_PASSWORD: 'pw-should-not-leak' },
    })
    expectExit(inherited, 0, 'run inherited handle')
    assert.equal(inherited.stdout, '[masked:Y]\nk=unset p=unset\n')

    // --no-inherit: only the resolved values (plus PATH and the like).
    const isolated = cli(['run', '--no-inherit', '--env-file', envFile, '--', 'sh', '-c', 'echo "${MARKER:-none}"'], {
      ...asAgent,
      env: { ...asAgent.env, MARKER: 'inherited' },
    })
    expectExit(isolated, 0, 'run --no-inherit')
    assert.equal(isolated.stdout, 'none\n')

    // Exit codes: the child's, 128+signal, 127, 126, 125.
    expectExit(cli(['run', '--', 'sh', '-c', 'exit 3'], asAgent), 3, 'child exit code')
    expectExit(cli(['run', '--', 'sh', '-c', 'kill -TERM $$'], asAgent), 143, 'child killed by SIGTERM')
    expectExit(cli(['run', '--', 'pastevault-no-such-command-xyz'], asAgent), 127, 'command not found')
    const notExecutable = path.join(temporaryRoot, 'not-executable.sh')
    writeFileSync(notExecutable, 'echo hi\n', { mode: 0o600 })
    expectExit(cli(['run', '--', notExecutable], asAgent), 126, 'command not executable')
    const missing = path.join(temporaryRoot, 'missing.env.pv')
    writeFileSync(missing, 'Z=pv://secret/NOT_THERE\n')
    const unresolved = cli(['run', '--env-file', missing, '--', 'true'], asAgent)
    expectExit(unresolved, 125, 'unresolvable handle')
    assert.match(unresolved.stderr, /NOT_THERE/)

    // Signals are forwarded to the child; run reports 128+signal.
    const trap = path.join(temporaryRoot, 'trap.sh')
    writeFileSync(trap, 'trap "echo got-term; exit 42" TERM\necho ready\nwhile :; do sleep 0.1; done\n')
    const running = cliAsync(['run', '--', 'sh', trap], asAgent)
    for (let attempt = 0; attempt < 100 && !running.stdout().includes('ready'); attempt++) {
      await sleep(100)
    }
    assert.match(running.stdout(), /ready/)
    running.child.kill('SIGTERM')
    const trapped = await running.done
    assert.equal(trapped.status, 42, `forwarded SIGTERM: ${trapped.stdout}${trapped.stderr}`)
    assert.match(trapped.stdout, /got-term/)
  }

  // ── inject ───────────────────────────────────────────────────────────
  {
    const template = path.join(temporaryRoot, 'config.tmpl')
    writeFileSync(template, 'api_key: {{ pv://secret/OPENAI_API_KEY }}\nurl: {{pv://secret/DB_URL}}\nkeep: {{ not.a.handle }}\n')
    const output = path.join(temporaryRoot, 'config.yml')
    const injected = cliJson(['inject', '-i', template, '-o', output], asAgent)
    assert.equal(injected.placeholders, 2)
    assertPrivate(output)
    assert.equal(
      readFileSync(output, 'utf8'),
      `api_key: ${secretValue}\nurl: postgres://u:Secr3tPassw0rd@db/x\nkeep: {{ not.a.handle }}\n`
    )
    expectExit(cli(['inject', '-i', template, '-o', output], asAgent), 13, 'inject onto an existing file')
    const broken = path.join(temporaryRoot, 'broken.tmpl')
    writeFileSync(broken, 'x: {{ pv://secret/NOPE }}\n')
    expectExit(cli(['inject', '-i', broken, '--stdout'], asAgent), 125, 'inject with an unresolvable handle')
  }

  // ── get --save, share handles in run ────────────────────────────────
  if (isPosix) {
    const shareValue = 'SHARED_TOKEN=abc123-shared-secret-value\nOTHER=1\n'
    const unlimited = cliJson(['put', '-', '--expires', '1h'], { config: newConfigDir(), input: shareValue })
    const limited = cliJson(['put', '-', '--max-views', '2'], { config: newConfigDir(), input: shareValue })
    const slug = unlimited.slug
    const key = unlimited.url.split('#k=')[1]

    const handleFile = path.join(temporaryRoot, 'share.env.pv')
    writeFileSync(handleFile, `S=pv://share/${slug}?var=SHARED_TOKEN#k=${key}\n`)
    const viaShare = cli(['run', '--env-file', handleFile, '--', 'sh', '-c', 'echo "$S"; printf %s "$S" | wc -c'], asAgent)
    expectExit(viaShare, 0, 'run with a share handle')
    assert.equal(viaShare.stdout.split('\n')[0], '[masked:S]')
    assert.equal(viaShare.stdout.split('\n')[1].trim(), String('abc123-shared-secret-value'.length))

    // A view-limited share is refused (it would burn), nothing consumed.
    writeFileSync(handleFile, `S=pv://share/${limited.slug}#k=${limited.url.split('#k=')[1]}\n`)
    const refused = cli(['run', '--env-file', handleFile, '--', 'true'], asAgent)
    expectExit(refused, 125, 'run with a view-limited share')
    assert.match(refused.stderr, /--save NAME/)
    const [limitedRow] = await database.query('SELECT "view_count" FROM "Paste" WHERE "slug" = $1', limited.slug)
    assert.equal(Number(limitedRow.view_count), 0)

    // get --save stores it (one view), then pv://secret works.
    const saved = cliJson(['get', limited.url, '--save', 'SHARED_ENV'], asAgent)
    assert.equal(saved.saved_as, 'pv://secret/SHARED_ENV')
    assert.equal(saved.content, undefined)
    expectExit(cli(['get', limited.url, '--save', 'SHARED_ENV'], asAgent), 13, 'get --save onto an existing secret (before consuming)')
    const [afterSave] = await database.query('SELECT "view_count" FROM "Paste" WHERE "slug" = $1', limited.slug)
    assert.equal(Number(afterSave.view_count), 1)
    writeFileSync(handleFile, 'T=pv://secret/SHARED_ENV?var=SHARED_TOKEN\n')
    const fromSaved = cli(['run', '--env-file', handleFile, '--no-mask', '--', 'sh', '-c', 'echo "$T"'], asAgent)
    expectExit(fromSaved, 0, 'run with a saved share')
    assert.equal(fromSaved.stdout, 'abc123-shared-secret-value\n')
  }

  // ── request --wait ───────────────────────────────────────────────────
  {
    const waiting = cliAsync(['request', 'DB_PASSWORD', '--why', 'migrate', '--wait', '--json'], asAgent)
    let pending
    for (let attempt = 0; attempt < 100 && !pending; attempt++) {
      await sleep(100)
      const directory = path.join(agentConfig, 'requests')
      const files = existsSync(directory) ? readdirSync(directory).filter((name) => name.endsWith('.json')) : []
      if (files.length === 1) {
        pending = JSON.parse(readFileSync(path.join(directory, files[0]), 'utf8'))
      }
    }
    assert(pending, 'request --wait wrote its request file')
    expectExit(
      cli(['request', 'fulfil', pending.code, '--fingerprint', pending.fingerprint.slice(0, 13), '--from-stdin'], {
        config: humanConfig,
        input: 'hunter2-hunter2',
      }),
      0,
      'fulfil with a short fingerprint'
    )
    const result = await waiting.done
    expectExit(result, 0, 'request --wait')
    const output = JSON.parse(result.stdout)
    assert.equal(output.handle, 'pv://secret/DB_PASSWORD')
    assert.match(result.stderr, new RegExp(`/r/${pending.code}#fp=${pending.fingerprint}`))
  }

  // ── decline → exit 6, cancel, expiry → exit 5 ──────────────────────
  {
    const declined = cliJson(['request', 'DECLINED_ONE'], asAgent)
    const declineResult = cliJson(['request', 'decline', declined.code], { config: humanConfig })
    assert.equal(declineResult.status, 'declined')
    expectExit(cli(['await', declined.code], asAgent), 6, 'await a declined request')
    assert(!existsSync(requestFile(agentConfig, declined.id)))
    // Answering a declined request is a 409-ish refusal before anything is read.
    expectExit(cli(['request', 'fulfil', declined.url, '--from-stdin'], { config: humanConfig, input: 'x' }), 6, 'fulfil a declined request')

    const cancelled = cliJson(['request', 'CANCELLED_ONE'], asAgent)
    const cancelResult = cliJson(['request', 'cancel', cancelled.code], asAgent)
    assert.equal(cancelResult.cancelled[0].status, 'cancelled')
    assert(!existsSync(requestFile(agentConfig, cancelled.id)))
    assert.equal((await requestRow(cancelled.id)).status, 'cancelled')

    const expiring = cliJson(['request', 'EXPIRING_ONE', '--ttl', '5s'], asAgent)
    await sleep(6_000)
    const expired = cli(['await', expiring.code, '--timeout', '30s'], asAgent)
    assert([5, 9].includes(expired.status), `await an expired request: exit ${expired.status}\n${expired.stderr}`)
    assert.equal((await requestRow(expiring.id)).status, 'expired')

    // Below the server minimum.
    expectExit(cli(['request', 'TOO_SHORT', '--ttl', '2s'], asAgent), 2, 'ttl below the minimum')

    const listed = cliJson(['request', 'list'], asAgent)
    const statuses = Object.fromEntries(listed.requests.map((entry) => [entry.name, entry.status]))
    assert.equal(statuses.OPENAI_API_KEY, 'delivered')
    assert.equal(statuses.DECLINED_ONE, 'declined')
    assert.equal(statuses.CANCELLED_ONE, 'cancelled')
    assert.equal(statuses.EXPIRING_ONE, 'expired')
    assert(!JSON.stringify(listed).includes('ciphertext'))
  }

  // ── API rules: other accounts, tokens, slow_down, lease, ack ────────
  {
    const target = cliJson(['request', 'LEASED'], asAgent)
    const pending = JSON.parse(readFileSync(requestFile(agentConfig, target.id), 'utf8'))
    const agentHeaders = { authorization: `Bearer ${agentToken}` }

    // Another account's code is a 404 (by-code and the CLI).
    {
      const { response } = await request(baseUrl, `/api/secret-requests/by-code/${target.code}`, { headers: other.headers })
      assert.equal(response.status, 404)
      expectExit(cli(['request', 'fulfil', target.url, '--from-stdin'], { config: outsiderConfig, input: 'x' }), 4, 'fulfil another account\'s request')
      const fulfill = await jsonRequest(
        baseUrl,
        `/api/secret-requests/${target.id}/fulfill`,
        { kind: 'text', ciphertext: 'A'.repeat(100), nonce: 'A'.repeat(32), wrapped_key: 'A'.repeat(140) },
        other.headers
      )
      assert.equal(fulfill.response.status, 404)
      const decline = await request(baseUrl, `/api/secret-requests/${target.id}/decline`, { method: 'POST', headers: other.headers })
      assert.equal(decline.response.status, 404)
    }

    // Tokens can't read the page data, answer or decline.
    {
      const byCode = await request(baseUrl, `/api/secret-requests/by-code/${target.code}`, { headers: agentHeaders })
      assert.equal(byCode.response.status, 403)
      assert.equal(byCode.body.error, 'session_required')
      const fulfill = await jsonRequest(
        baseUrl,
        `/api/secret-requests/${target.id}/fulfill`,
        { kind: 'text', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAA', nonce: 'A'.repeat(32), wrapped_key: 'A'.repeat(140) },
        agentHeaders
      )
      assert.equal(fulfill.response.status, 403)
      assert.equal(fulfill.body.error, 'session_required')
      const decline = await request(baseUrl, `/api/secret-requests/${target.id}/decline`, { method: 'POST', headers: agentHeaders })
      assert.equal(decline.response.status, 403)
      // A cookie session from an untrusted origin is refused (CSRF).
      const csrf = await jsonRequest(
        baseUrl,
        `/api/secret-requests/${target.id}/fulfill`,
        { kind: 'text', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAA', nonce: 'A'.repeat(32), wrapped_key: 'A'.repeat(140) },
        { cookie: owner.cookie, origin: 'https://evil.example' }
      )
      assert.equal(csrf.response.status, 403)
      assert.equal(csrf.body.error, 'origin_not_allowed')
      // JSON only.
      const plain = await request(baseUrl, `/api/secret-requests/${target.id}/fulfill`, {
        method: 'POST',
        headers: { ...owner.headers, 'content-type': 'text/plain' },
        body: 'x',
      })
      assert.equal(plain.response.status, 415)
    }

    // Polling: wrong token 403, too fast 429 slow_down.
    {
      const wrong = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: 'nope' }, agentHeaders)
      assert.equal(wrong.response.status, 403)
      const firstPoll = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: pending.poll_token }, agentHeaders)
      assert.equal(firstPoll.response.status, 200)
      assert.deepEqual(firstPoll.body, { status: 'pending', interval: 3 })
      const fast = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: pending.poll_token }, agentHeaders)
      assert.equal(fast.response.status, 429)
      assert.equal(fast.body.error, 'slow_down')
    }

    // Too large, wrong kind.
    {
      const big = await jsonRequest(
        baseUrl,
        `/api/secret-requests/${target.id}/fulfill`,
        { kind: 'file', ciphertext: 'A'.repeat(100), nonce: 'A'.repeat(32), wrapped_key: 'A'.repeat(140) },
        owner.headers
      )
      assert.equal(big.response.status, 400)
      assert.equal(big.body.code, 'kind_not_accepted')
    }

    expectExit(cli(['request', 'fulfil', target.url, '--from-stdin'], { config: humanConfig, input: 'lease-secret-value' }), 0, 'fulfil')
    // A second answer conflicts.
    const again = await jsonRequest(
      baseUrl,
      `/api/secret-requests/${target.id}/fulfill`,
      { kind: 'text', ciphertext: 'A'.repeat(100), nonce: 'A'.repeat(32), wrapped_key: 'A'.repeat(140) },
      owner.headers
    )
    assert.equal(again.response.status, 409)

    // Delivered once, re-pollable within the lease with the same payload.
    await sleep(3_100)
    const delivered = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: pending.poll_token }, agentHeaders)
    assert.equal(delivered.response.status, 200)
    assert.equal(delivered.body.status, 'fulfilled')
    assert.equal(delivered.body.kind, 'text')
    assert((await requestRow(target.id)).status, 'delivered')
    await sleep(3_100)
    const repoll = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: pending.poll_token }, agentHeaders)
    assert.equal(repoll.response.status, 200)
    assert.equal(repoll.body.ciphertext, delivered.body.ciphertext)
    assert.equal(repoll.body.wrapped_key, delivered.body.wrapped_key)

    // The CLI (crash recovery) stores it from the re-poll and acks.
    await sleep(3_100)
    const recovered = cliJson(['await', target.code], asAgent)
    assert.equal(recovered.handle, 'pv://secret/LEASED')
    const wiped = await requestRow(target.id)
    assert.equal(wiped.response_ciphertext, null)
    assert(wiped.acked_at)
    await sleep(3_100)
    const gone = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/poll`, { poll_token: pending.poll_token }, agentHeaders)
    assert.equal(gone.response.status, 200)
    assert.deepEqual(gone.body, { status: 'delivered', interval: 3 })

    // Ack directly (idempotent 204), and cancel after delivery is refused.
    const ack = await jsonRequest(baseUrl, `/api/secret-requests/${target.id}/ack`, { poll_token: pending.poll_token }, agentHeaders)
    assert.equal(ack.response.status, 204)
    const cancelAfter = await request(baseUrl, `/api/secret-requests/${target.id}`, { method: 'DELETE', headers: agentHeaders })
    assert.equal(cancelAfter.response.status, 409)
  }

  // ── create rules and limits ──────────────────────────────────────────
  {
    const { publicKey } = generateKeyPairSync('x25519')
    const publicKeyText = publicKey.export({ format: 'jwk' }).x
    const fingerprint = agentFingerprint(Buffer.from(publicKeyText, 'base64url'))
    const create = (body, headers = owner.headers) =>
      jsonRequest(baseUrl, '/api/secret-requests', { name: 'LIMIT', public_key: publicKeyText, fingerprint, agent_id: agent.id, ...body }, headers)

    assert.equal((await create({ fingerprint: agent.fingerprint })).body.code, 'fingerprint_mismatch')
    assert.equal((await create({ agent_id: 'nope' })).body.code, 'requester_agent_unknown')
    assert.equal((await create({ ttl_seconds: 4 })).response.status, 400)
    assert.equal((await create({ ttl_seconds: 86_401 })).response.status, 400)
    assert.equal((await create({ name: '1BAD' })).response.status, 400)
    assert.equal((await create({ reason: 'a‮b' })).response.status, 400)
    assert.equal((await create({}, other.headers)).body.code, 'requester_agent_unknown')
    assert.equal((await create({}, {})).response.status, 401)

    // A token without requests:create gets 403.
    const limitedToken = cliJson(['token', 'create', '--name', 'no-requests', '--scopes', 'shares:create'], { config: agentConfig }).token
    const noScope = await create({}, { authorization: `Bearer ${limitedToken}` })
    assert.equal(noScope.response.status, 403)
    assert.equal(noScope.body.error, 'insufficient_scope')

    // 20 pending per account: a fresh account with its own agent.
    const third = await signUp(baseUrl, 'limits')
    const thirdKey = generateKeyPairSync('x25519').publicKey.export({ format: 'jwk' }).x
    const registered = await jsonRequest(
      baseUrl,
      '/api/agents',
      { name: 'limits', public_key: thirdKey, fingerprint: agentFingerprint(Buffer.from(thirdKey, 'base64url')) },
      third.headers
    )
    assert.equal(registered.response.status, 201)
    const createThird = () =>
      jsonRequest(
        baseUrl,
        '/api/secret-requests',
        { name: 'LIMIT', public_key: publicKeyText, fingerprint, agent_id: registered.body.agent.id },
        third.headers
      )
    for (let index = 0; index < 20; index++) {
      const created = await createThird()
      assert.equal(created.response.status, 201, JSON.stringify(created.body))
      assert.equal(created.body.url_path, `/r/${created.body.code}`)
      assert.equal(created.body.interval, 3)
    }
    const overLimit = await createThird()
    assert.equal(overLimit.response.status, 429)
    assert.equal(overLimit.body.error, 'too_many_pending_requests')

    const listed = await request(baseUrl, '/api/account/secret-requests?status=pending', { headers: third.headers })
    assert.equal(listed.body.requests.length, 20)
    assert(!JSON.stringify(listed.body).includes('poll_token'))
  }

  // ── by-code rate limit: misses (guessing) are limited, the page polling
  // its own request is not ─────────────────────────────────────────────
  {
    const guesser = await signUp(baseUrl, 'guesser')
    for (let index = 0; index < 20; index++) {
      const { response } = await request(baseUrl, `/api/secret-requests/by-code/WXYZ-${String(2222 + index).replace(/[01]/g, '2')}`, {
        headers: guesser.headers,
      })
      assert.equal(response.status, 404)
    }
    const limited = await request(baseUrl, '/api/secret-requests/by-code/WXYZ-9999', { headers: guesser.headers })
    assert.equal(limited.response.status, 429)

    const polled = cliJson(['request', 'POLLED'], asAgent)
    for (let index = 0; index < 25; index++) {
      const { response } = await request(baseUrl, `/api/secret-requests/by-code/${polled.code}`, { headers: owner.headers })
      assert.equal(response.status, 200, `own request lookup ${index}`)
    }
  }

  console.log(
    `E2E requests test passed (${provider}): request, fulfil, await, store, run masking, inject, get --save, decline, expiry, slow_down, lease, limits`
  )
})
