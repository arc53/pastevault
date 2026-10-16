// The MCP server (pastevault mcp) end to end over stdio against a real
// server: initialize, tools/list, send_text → receive to a file (plain and
// sealed to an agent), path confinement, request_secret answered with the
// CLI's request fulfil → request_status → pv://secret handle, URL-mode
// elicitation, list_secrets, share_status, audit and revoke_share. Every
// line the server writes to stdout must be a JSON-RPC message.
// Builds cmd/pastevault with Go, or uses PASTEVAULT_CLI_BIN.
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { projectRoot, runSuite, signUp, sleep } from './lib/harness.mjs'

function hasGo() {
  return spawnSync('go', ['version'], { encoding: 'utf8' }).status === 0
}

if (!process.env.PASTEVAULT_CLI_BIN && !hasGo()) {
  if (process.env.CI) {
    console.error('e2e-mcp: Go is required in CI (or set PASTEVAULT_CLI_BIN)')
    process.exit(1)
  }
  console.warn('e2e-mcp: SKIPPED, no Go toolchain found (install Go or set PASTEVAULT_CLI_BIN)')
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
const TOOLS = [
  'audit',
  'list_secrets',
  'receive',
  'request_secret',
  'request_status',
  'revoke_share',
  'send_file',
  'send_text',
  'share_status',
]

// A minimal MCP client over a child's stdio (newline-delimited JSON-RPC).
class McpClient {
  constructor(child, { onRequest } = {}) {
    this.child = child
    this.nextId = 1
    this.pending = new Map()
    this.notifications = []
    this.stdoutViolations = []
    this.stderr = ''
    this.onRequest = onRequest
    let buffer = ''
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      buffer += chunk
      let newline
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline)
        buffer = buffer.slice(newline + 1)
        this.onLine(line)
      }
    })
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => (this.stderr += chunk))
    this.exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })))
  }

  onLine(line) {
    if (line.trim() === '') {
      return
    }
    let message
    try {
      message = JSON.parse(line)
    } catch {
      this.stdoutViolations.push(line)
      return
    }
    if (message.jsonrpc !== '2.0') {
      this.stdoutViolations.push(line)
      return
    }
    if (message.method && message.id !== undefined) {
      // A server → client request (elicitation, roots).
      Promise.resolve(this.onRequest ? this.onRequest(message) : undefined).then((reply) => {
        const response = reply?.error
          ? { jsonrpc: '2.0', id: message.id, error: reply.error }
          : reply
            ? { jsonrpc: '2.0', id: message.id, result: reply }
            : { jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }
        this.child.stdin.write(JSON.stringify(response) + '\n')
      })
      return
    }
    if (message.method) {
      this.notifications.push(message)
      return
    }
    const waiter = this.pending.get(message.id)
    if (waiter) {
      this.pending.delete(message.id)
      waiter(message)
    }
  }

  request(method, params, timeoutMs = 60_000) {
    const id = this.nextId++
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`${method}: no response in ${timeoutMs} ms\nstderr:\n${this.stderr}`))
      }, timeoutMs)
      this.pending.set(id, (message) => {
        clearTimeout(timer)
        resolve(message)
      })
    })
    this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n')
    return response
  }

  notify(method, params) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, ...(params ? { params } : {}) }) + '\n')
  }

  async initialize(capabilities = {}) {
    const response = await this.request('initialize', {
      protocolVersion: '2025-11-25',
      capabilities,
      clientInfo: { name: 'e2e-mcp', version: '1' },
    })
    assert.equal(response.error, undefined, JSON.stringify(response.error))
    this.notify('notifications/initialized')
    return response.result
  }

  // callTool returns {result, structured, error} with the text content
  // parsed as JSON.
  async callTool(name, args = {}, timeoutMs) {
    const response = await this.request('tools/call', { name, arguments: args }, timeoutMs)
    assert.equal(response.error, undefined, `${name}: protocol error ${JSON.stringify(response.error)}`)
    const result = response.result
    assert.equal(result.content.length, 1, `${name}: one content block`)
    assert.equal(result.content[0].type, 'text')
    const parsed = JSON.parse(result.content[0].text)
    if (result.isError) {
      assert.equal(result.structuredContent, undefined, `${name}: errors carry no structured content`)
      return { result, error: parsed.error }
    }
    assert.deepEqual(result.structuredContent, parsed, `${name}: structuredContent equals the text content`)
    return { result, structured: parsed }
  }

  async close() {
    this.child.stdin.end()
    const exit = await Promise.race([this.exited, sleep(10_000).then(() => ({ code: 'timeout' }))])
    if (exit.code === 'timeout') {
      this.child.kill('SIGKILL')
    }
    assert.equal(exit.code, 0, `mcp exit ${exit.code}\nstderr:\n${this.stderr}`)
    assert.deepEqual(this.stdoutViolations, [], 'stdout carries only JSON-RPC messages')
  }
}

await runSuite('mcp', {}, async ({ startServer, temporaryRoot }) => {
  const binary = buildCli(temporaryRoot)
  const server = await startServer({
    label: 'mcp',
    environment: { SECRET_REQUEST_MIN_TTL_SECONDS: '5' },
  })
  const { baseUrl, database } = server
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

  function cli(args, { input = '', config, env = {} } = {}) {
    const result = spawnSync(binary, args, {
      cwd: temporaryRoot,
      input,
      encoding: 'utf8',
      env: cliEnvironment(config, env),
      timeout: 90_000,
    })
    return { status: result.status, stdout: result.stdout, stderr: result.stderr }
  }

  function cliJson(args, options) {
    const result = cli([...args, '--json'], options)
    assert.equal(result.status, 0, `${args.join(' ')}: exit ${result.status}\n${result.stdout}\n${result.stderr}`)
    return JSON.parse(result.stdout)
  }

  function startMcp(args, { config, env = {}, cwd, onRequest } = {}) {
    const child = spawn(binary, ['mcp', ...args], { cwd, env: cliEnvironment(config, env), stdio: ['pipe', 'pipe', 'pipe'] })
    return new McpClient(child, { onRequest })
  }

  // The agent's machine (agent key, agent-bound token) and the human's
  // (login session only), in one account.
  const owner = await signUp(baseUrl, 'mcp')
  const agentConfig = newConfigDir({ access_token: owner.sessionToken })
  const humanConfig = newConfigDir({ access_token: owner.sessionToken })
  cliJson(['agent', 'init', '--name', 'builder'], { config: agentConfig })
  const agentToken = cliJson(['token', 'create', '--name', 'mcp-bot', '--agent', 'builder'], { config: agentConfig }).token
  const workdir = path.join(temporaryRoot, 'project')
  mkdirSync(workdir)
  const outside = path.join(temporaryRoot, 'outside')
  mkdirSync(outside)
  writeFileSync(path.join(outside, 'private.txt'), 'not for sharing')
  writeFileSync(path.join(workdir, 'report.txt'), 'quarterly numbers\n')

  const asAgent = { config: agentConfig, env: { PASTEVAULT_TOKEN: agentToken }, cwd: workdir }
  const mcp = startMcp(['--root', workdir], asAgent)

  // ── initialize, tools/list ──────────────────────────────────────────
  {
    const initialized = await mcp.initialize()
    assert.equal(initialized.protocolVersion, '2025-11-25')
    assert.equal(initialized.serverInfo.name, 'pastevault')
    assert(initialized.capabilities.tools)
    assert.match(initialized.instructions, /request_secret/)

    const { result } = await mcp.request('tools/list', {})
    const names = result.tools.map((tool) => tool.name).sort()
    assert.deepEqual(names, TOOLS)
    for (const tool of result.tools) {
      assert(!tool.name.includes('read'), `${tool.name}: no tool reads secrets`)
      assert.equal(tool.inputSchema.type, 'object')
      assert.equal(tool.inputSchema.additionalProperties, false, `${tool.name}: additionalProperties false`)
      assert(tool.outputSchema, `${tool.name}: output schema`)
      assert(tool.annotations, `${tool.name}: annotations`)
    }
    const byName = Object.fromEntries(result.tools.map((tool) => [tool.name, tool]))
    assert.equal(byName.revoke_share.annotations.destructiveHint, true)
    for (const name of ['list_secrets', 'share_status', 'audit']) {
      assert.equal(byName[name].annotations.readOnlyHint, true, `${name} is read-only`)
    }
    assert.equal(byName.request_status.annotations.readOnlyHint, false, 'request_status writes the store')
    assert.equal(byName.send_text.annotations.openWorldHint, true)
    assert.equal(byName.receive.annotations.openWorldHint, true)
  }

  // ── send_text → receive to a file ───────────────────────────────────
  let firstSlug
  {
    const text = 'deploy checklist\n1. migrate\n2. restart\n'
    const { structured: sent } = await mcp.callTool('send_text', { text, title: 'checklist' })
    assert.equal(sent.kind, 'paste')
    assert.equal(sent.max_views, 1)
    assert.equal(sent.key_in_url, true)
    assert.match(sent.url, new RegExp(`^${baseUrl}/p/[A-Za-z0-9_-]{12}#k=`))
    firstSlug = sent.slug
    const [row] = await database.query('SELECT "ciphertext", "expires_at", "created_at" FROM "Paste" WHERE "slug" = $1', firstSlug)
    assert(!row.ciphertext.includes('deploy checklist'))
    const lifetime = new Date(row.expires_at) - new Date(row.created_at)
    assert(lifetime > 55 * 60_000 && lifetime < 65 * 60_000, 'send_text defaults to a 1h expiry')

    const { structured: received } = await mcp.callTool('receive', { ref: sent.url, output_path: 'checklist.txt' })
    const target = path.join(workdir, 'checklist.txt')
    assert.equal(readFileSync(target, 'utf8'), text)
    assert.equal(received.kind, 'paste')
    assert.equal(received.burned, true)
    assert.equal(received.content, undefined)
    if (isPosix) {
      assert.equal(statSync(target).mode & 0o777, 0o600)
    }

    // Burned now: the CLI's exit code comes back as the tool error.
    const { error } = await mcp.callTool('receive', { ref: sent.url, output_path: 'again.txt' })
    assert.equal(error.exit_code, 5)
    assert.equal(error.code, 'gone')
  }

  // ── confinement ─────────────────────────────────────────────────────
  {
    const { error: readError } = await mcp.callTool('send_file', { paths: [path.join(outside, 'private.txt')] })
    assert.equal(readError.code, 'path_refused')
    assert.equal(readError.exit_code, 13)

    const { structured: sent } = await mcp.callTool('send_text', { text: 'confined', max_views: 2 })
    const { error: writeError } = await mcp.callTool('receive', { ref: sent.url, output_path: path.join(outside, 'x.txt') })
    assert.equal(writeError.code, 'path_refused')
    const [row] = await database.query('SELECT "view_count" FROM "Paste" WHERE "slug" = $1', sent.slug)
    assert.equal(Number(row.view_count), 0, 'a refused receive opens nothing')

    // Without a destination, receive uses pastevault-received/ in the root.
    const { structured: defaulted } = await mcp.callTool('receive', { ref: sent.url })
    assert.equal(path.dirname(defaulted.written_to), path.join(workdir, 'pastevault-received'))
    assert.equal(readFileSync(defaulted.written_to, 'utf8'), 'confined')
    const { error: noPlaintext } = await mcp.callTool('receive', { ref: sent.url, allow_plaintext: true })
    assert.match(noPlaintext.message, /--allow-plaintext/)

    const { structured: file } = await mcp.callTool('send_file', { paths: ['report.txt'] })
    assert.equal(file.kind, 'file_share')
    assert.deepEqual(file.files, [{ name: 'report.txt', size: 'quarterly numbers\n'.length }])
    mkdirSync(path.join(workdir, 'downloads'))
    const { structured: got } = await mcp.callTool('receive', { ref: file.url, output_path: 'downloads/' })
    assert.equal(readFileSync(path.join(workdir, 'downloads', 'report.txt'), 'utf8'), 'quarterly numbers\n')
    assert.equal(got.files.length, 1)
  }

  // ── sender-chosen names never become config files ───────────────────
  {
    const { structured: planted } = await mcp.callTool('send_text', { text: '{"mcpServers":{"evil":{"command":"sh"}}}', title: '.mcp.json' })
    const { structured: got } = await mcp.callTool('receive', { ref: planted.url, output_path: 'inbox/' })
    assert(!existsSync(path.join(workdir, 'inbox', '.mcp.json')), 'a title .mcp.json must not land as .mcp.json')
    assert.equal(path.basename(got.written_to), `received-${planted.slug}-mcp.json`)
    assert.equal(readFileSync(got.written_to, 'utf8'), '{"mcpServers":{"evil":{"command":"sh"}}}')

    // Explicit risky names and overwriting files receive didn't write are refused before opening.
    writeFileSync(path.join(workdir, 'CLAUDE.md'), 'project rules')
    const { structured: second } = await mcp.callTool('send_text', { text: 'replace the rules', max_views: 2 })
    for (const args of [{ output_path: 'CLAUDE.md', overwrite: true }, { output_path: '.envrc' }, { output_path: '.github/workflows/x.yml' }]) {
      const { error } = await mcp.callTool('receive', { ref: second.url, ...args })
      assert.equal(error.code, 'path_refused', JSON.stringify(args))
    }
    assert.equal(readFileSync(path.join(workdir, 'CLAUDE.md'), 'utf8'), 'project rules')
    const [row] = await database.query('SELECT "view_count" FROM "Paste" WHERE "slug" = $1', second.slug)
    assert.equal(Number(row.view_count), 0, 'refused receives open nothing')

    // Shares on other hosts are refused.
    const { error: foreign } = await mcp.callTool('receive', { ref: 'https://other.example/p/abcdefghijkl', output_path: 'x.txt' })
    assert.equal(foreign.code, 'host_not_allowed')
  }

  // ── sealed to an agent (to:) ────────────────────────────────────────
  {
    const { structured: sealed } = await mcp.callTool('send_text', { text: 'for the builder only', to: 'builder' })
    assert.equal(sealed.key_in_url, false)
    assert(!sealed.url.includes('#'))
    assert.equal(sealed.recipient.name, 'builder')
    const { structured: opened } = await mcp.callTool('receive', { ref: sealed.url, output_path: 'sealed.txt' })
    assert.equal(opened.recipient.name, 'builder')
    assert.equal(readFileSync(path.join(workdir, 'sealed.txt'), 'utf8'), 'for the builder only')
  }

  // ── request_secret (no elicitation) → fulfil → request_status ───────
  const secretValue = 'sk-mcp-' + 'Q7x'.repeat(8) + '-end'
  {
    const { structured: requested } = await mcp.callTool('request_secret', { name: 'OPENAI_API_KEY', reason: 'run the evals' })
    assert.equal(requested.status, 'pending')
    assert.match(requested.url, new RegExp(`^${baseUrl}/r/[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}#fp=pvk1_`))
    assert.match(requested.message, /request_status/)
    assert.equal(requested.handle, undefined)

    const fulfilled = cli(['request', 'fulfil', requested.url, '--from-stdin', '--json'], { config: humanConfig, input: secretValue })
    assert.equal(fulfilled.status, 0, fulfilled.stderr)

    let status
    for (let attempt = 0; attempt < 20; attempt++) {
      ;({ structured: status } = await mcp.callTool('request_status', { request_id: requested.request_id, wait_seconds: attempt === 0 ? 10 : 0 }))
      if (status.status !== 'pending') {
        break
      }
      await sleep(1000)
    }
    assert.equal(status.status, 'delivered')
    assert.equal(status.handle, 'pv://secret/OPENAI_API_KEY')

    const listedRaw = await mcp.request('tools/call', { name: 'list_secrets', arguments: {} })
    assert(!JSON.stringify(listedRaw).includes(secretValue), 'list_secrets never returns values')
    const { structured: listed } = await mcp.callTool('list_secrets')
    assert.deepEqual(
      listed.secrets.map((entry) => [entry.name, entry.handle, entry.kind, entry.source.type]),
      [['OPENAI_API_KEY', 'pv://secret/OPENAI_API_KEY', 'text', 'request']]
    )

    // The handle works with run (the value never went through MCP).
    if (isPosix) {
      const envFile = path.join(workdir, '.env.pv')
      writeFileSync(envFile, 'KEY=pv://secret/OPENAI_API_KEY\n')
      const run = cli(['run', '--env-file', envFile, '--no-mask', '--', 'sh', '-c', 'printf %s "$KEY"'], { config: agentConfig })
      assert.equal(run.stdout, secretValue)
    }
  }

  // ── share_status, audit, revoke_share ───────────────────────────────
  {
    const { structured: status } = await mcp.callTool('share_status', { ref: firstSlug })
    assert.equal(status.slug, firstSlug)
    assert.equal(status.status, 'burned')
    assert.equal(status.view_count, 1)
    assert(status.events.some((event) => event.event === 'share.viewed'))

    const { structured: pendingShare } = await mcp.callTool('send_text', { text: 'watch me' })
    const { structured: waited } = await mcp.callTool('share_status', { ref: pendingShare.slug, wait_for: 'viewed', wait_seconds: 1 })
    assert.equal(waited.timed_out, true)
    assert.equal(waited.view_count, 0)

    const { structured: audit } = await mcp.callTool('audit', { limit: 50 })
    const events = audit.events.map((event) => event.event)
    for (const name of ['share.created', 'share.burned', 'request.fulfilled', 'request.delivered']) {
      assert(events.includes(name), `audit has ${name}`)
    }

    const { structured: revoked } = await mcp.callTool('revoke_share', { ref: pendingShare.url })
    assert.equal(revoked.slug, pendingShare.slug)
    const { error: gone } = await mcp.callTool('receive', { ref: pendingShare.url, output_path: 'revoked.txt' })
    assert.equal(gone.exit_code, 4)
  }

  await mcp.close()

  // ── URL-mode elicitation over stdio ─────────────────────────────────
  {
    const elicitations = []
    const elicitingConfig = agentConfig
    const eliciting = startMcp([], {
      ...asAgent,
      config: elicitingConfig,
      onRequest: async (message) => {
        if (message.method === 'roots/list') {
          return { roots: [{ uri: `file://${workdir}`, name: 'project' }] }
        }
        if (message.method !== 'elicitation/create') {
          return undefined
        }
        elicitations.push(message.params)
        // The human opens the link and answers.
        const answered = cli(['request', 'fulfil', message.params.url, '--from-stdin'], { config: humanConfig, input: 'db-pass-Zz9Zz9Zz9' })
        assert.equal(answered.status, 0, answered.stderr)
        return { action: 'accept' }
      },
    })
    await eliciting.initialize({ elicitation: { url: {} }, roots: { listChanged: false } })
    const { structured, result } = await eliciting.callTool('request_secret', { name: 'DB_PASSWORD', reason: 'migrate', timeout_seconds: 60 }, 90_000)
    assert.equal(elicitations.length, 1)
    assert.equal(elicitations[0].mode, 'url')
    assert.match(elicitations[0].url, /\/r\/[A-Z2-9-]{9}#fp=pvk1_/)
    assert.equal(elicitations[0].elicitationId, structured.request_id)
    assert.equal(structured.status, 'delivered')
    assert.equal(structured.handle, 'pv://secret/DB_PASSWORD')
    assert(!JSON.stringify(result).includes('db-pass-Zz9Zz9Zz9'))

    // The client's roots are used: send_file works there without --root.
    const { structured: shared } = await eliciting.callTool('send_file', { paths: [path.join(workdir, 'report.txt')] })
    assert.equal(shared.kind, 'file_share')
    await eliciting.close()
  }

  console.log('E2E mcp test passed (sqlite): stdio protocol, tools/list, send/receive, sealed shares, roots, request_secret with and without URL elicitation, list_secrets, share_status, audit, revoke')
})
