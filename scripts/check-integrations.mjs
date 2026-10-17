#!/usr/bin/env node
// Checks the agent integration packaging (docs/agents.md):
//   - every manifest is valid JSON with the fields its host requires
//     (Claude Code marketplace and plugin, Codex plugin and marketplace,
//     Gemini CLI extension at the repo root and in integrations/pastevault),
//   - every manifest starts the same MCP server (pastevault mcp),
//   - the skill's frontmatter follows the Agent Skills spec (agentskills.io),
//   - all versions equal package.json's version (and the release tag, when
//     given with --release-tag vX.Y.Z or PASTEVAULT_RELEASE_TAG),
//   - the skill only names tools the MCP server has,
//   - AGENTS.md and CLAUDE.md say the same thing.
// Usage: node scripts/check-integrations.mjs [--release-tag v1.2.3]
import { existsSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const pluginDir = 'integrations/pastevault'
const errors = []

function fail(message) {
  errors.push(message)
}

function read(relative) {
  const file = path.join(root, relative)
  if (!existsSync(file)) {
    fail(`${relative}: missing`)
    return null
  }
  return readFileSync(file, 'utf8')
}

function readJson(relative) {
  const text = read(relative)
  if (text === null) {
    return null
  }
  try {
    return JSON.parse(text)
  } catch (error) {
    fail(`${relative}: invalid JSON (${error.message})`)
    return null
  }
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== ''
}

function requireString(object, key, where) {
  if (!isNonEmptyString(object?.[key])) {
    fail(`${where}: "${key}" must be a non-empty string`)
    return false
  }
  return true
}

function isDirectory(relative) {
  const file = path.join(root, relative)
  return existsSync(file) && statSync(file).isDirectory()
}

function isFile(relative) {
  const file = path.join(root, relative)
  return existsSync(file) && statSync(file).isFile()
}

// A relative path inside the repository: "./a/b", no "..".
function checkRelativePath(value, where) {
  if (typeof value !== 'string' || !value.startsWith('./') || value.split('/').includes('..')) {
    fail(`${where}: "${value}" must be a relative path starting with ./ and without ..`)
    return false
  }
  return true
}

// ── versions ──────────────────────────────────────────────────────────────

const packageJson = readJson('package.json')
const expectedVersion = packageJson?.version
const argTag = process.argv.indexOf('--release-tag')
const releaseTag = (argTag >= 0 ? process.argv[argTag + 1] : process.env.PASTEVAULT_RELEASE_TAG) ?? ''
const versions = []

function checkVersion(value, where) {
  if (!isNonEmptyString(value)) {
    fail(`${where}: "version" must be set`)
    return
  }
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value)) {
    fail(`${where}: version "${value}" is not semver`)
  }
  versions.push([where, value])
}

// ── the MCP server every manifest starts ──────────────────────────────────

function checkMcpServer(server, where) {
  if (!server || typeof server !== 'object') {
    fail(`${where}: missing the "pastevault" MCP server`)
    return
  }
  if (server.command !== 'pastevault') {
    fail(`${where}: command must be "pastevault" (got ${JSON.stringify(server.command)})`)
  }
  if (!Array.isArray(server.args) || server.args[0] !== 'mcp') {
    fail(`${where}: args must start with "mcp" (got ${JSON.stringify(server.args)})`)
  }
  if (server.type !== undefined && server.type !== 'stdio') {
    fail(`${where}: type must be "stdio" when set`)
  }
}

// ── Claude Code: marketplace and plugin ───────────────────────────────────

const pluginName = 'pastevault'
const kebab = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

{
  const where = '.claude-plugin/marketplace.json'
  const marketplace = readJson(where)
  if (marketplace) {
    if (requireString(marketplace, 'name', where) && !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(marketplace.name)) {
      fail(`${where}: invalid marketplace name "${marketplace.name}"`)
    }
    requireString(marketplace.owner, 'name', `${where} owner`)
    if (!Array.isArray(marketplace.plugins) || marketplace.plugins.length === 0) {
      fail(`${where}: "plugins" must be a non-empty array`)
    } else {
      for (const [index, entry] of marketplace.plugins.entries()) {
        const at = `${where} plugins[${index}]`
        requireString(entry, 'name', at)
        if (checkRelativePath(entry.source, `${at} source`)) {
          const directory = entry.source.slice(2)
          if (!isFile(path.join(directory, '.claude-plugin/plugin.json'))) {
            fail(`${at}: ${entry.source} has no .claude-plugin/plugin.json`)
          }
        }
        if (entry.version !== undefined) {
          checkVersion(entry.version, at)
        }
      }
      if (!marketplace.plugins.some((entry) => entry.name === pluginName && entry.source === `./${pluginDir}`)) {
        fail(`${where}: needs the entry {"name":"${pluginName}","source":"./${pluginDir}"}`)
      }
    }
  }
}

{
  const where = `${pluginDir}/.claude-plugin/plugin.json`
  const plugin = readJson(where)
  if (plugin) {
    if (plugin.name !== pluginName || !kebab.test(plugin.name)) {
      fail(`${where}: name must be "${pluginName}" (kebab-case, the marketplace entry's name)`)
    }
    checkVersion(plugin.version, where)
    requireString(plugin, 'description', where)
    requireString(plugin.author, 'name', `${where} author`)
    requireString(plugin, 'license', where)
    if (plugin.mcpServers !== undefined) {
      fail(`${where}: declare the MCP server in .mcp.json only (shared with Codex)`)
    }
  }
}

{
  const where = `${pluginDir}/.mcp.json`
  const mcp = readJson(where)
  if (mcp) {
    const names = Object.keys(mcp.mcpServers ?? {})
    if (names.length !== 1 || names[0] !== 'pastevault') {
      fail(`${where}: must declare exactly one server, "pastevault"`)
    }
    checkMcpServer(mcp.mcpServers?.pastevault, where)
  }
}

// ── Codex: plugin (compatibility format) and marketplace ──────────────────

{
  const where = `${pluginDir}/.codex-plugin/plugin.json`
  const plugin = readJson(where)
  if (plugin) {
    if (plugin.name !== pluginName) {
      fail(`${where}: name must be "${pluginName}"`)
    }
    checkVersion(plugin.version, where)
    requireString(plugin, 'description', where)
    for (const key of ['skills', 'mcpServers']) {
      if (checkRelativePath(plugin[key], `${where} ${key}`)) {
        const target = path.join(pluginDir, plugin[key])
        const exists = key === 'skills' ? isDirectory(target) : isFile(target)
        if (!exists) {
          fail(`${where}: ${key} "${plugin[key]}" does not exist`)
        }
      }
    }
    requireString(plugin.interface, 'displayName', `${where} interface`)
    const prompts = plugin.interface?.defaultPrompt ?? []
    if (!Array.isArray(prompts) || prompts.length > 3 || prompts.some((prompt) => !isNonEmptyString(prompt) || prompt.length > 128)) {
      fail(`${where}: interface.defaultPrompt takes at most 3 prompts of at most 128 characters`)
    }
  }
}

{
  const where = '.agents/plugins/marketplace.json'
  const marketplace = readJson(where)
  if (marketplace) {
    requireString(marketplace, 'name', where)
    const entry = (marketplace.plugins ?? []).find((plugin) => plugin.name === pluginName)
    if (!entry) {
      fail(`${where}: needs a "${pluginName}" plugin entry`)
    } else {
      if (entry.source?.source !== 'local' || entry.source?.path !== `./${pluginDir}`) {
        fail(`${where}: the ${pluginName} source must be {"source":"local","path":"./${pluginDir}"}`)
      }
      if (!['AVAILABLE', 'INSTALLED_BY_DEFAULT', 'NOT_AVAILABLE'].includes(entry.policy?.installation)) {
        fail(`${where}: policy.installation must be AVAILABLE, INSTALLED_BY_DEFAULT or NOT_AVAILABLE`)
      }
      if (!['ON_INSTALL', 'ON_USE'].includes(entry.policy?.authentication)) {
        fail(`${where}: policy.authentication must be ON_INSTALL or ON_USE`)
      }
      requireString(entry, 'category', `${where} ${pluginName}`)
    }
  }
}

{
  const where = 'integrations/codex-config.toml'
  const toml = read(where)
  if (toml !== null) {
    const section = toml.split(/^\[mcp_servers\.pastevault\]\s*$/m)[1]?.split(/^\[/m)[0]
    if (section === undefined) {
      fail(`${where}: missing [mcp_servers.pastevault]`)
    } else {
      if (!/^command\s*=\s*"pastevault"\s*$/m.test(section)) {
        fail(`${where}: command must be "pastevault"`)
      }
      if (!/^args\s*=\s*\[\s*"mcp"/m.test(section)) {
        fail(`${where}: args must start with "mcp"`)
      }
    }
  }
}

// ── Gemini CLI: extension (repo root, and the plugin directory) ───────────

for (const [where, base] of [
  ['gemini-extension.json', '.'],
  [`${pluginDir}/gemini-extension.json`, pluginDir],
]) {
  const extension = readJson(where)
  if (!extension) {
    continue
  }
  if (extension.name !== pluginName || !/^[a-zA-Z0-9-]+$/.test(extension.name)) {
    fail(`${where}: name must be "${pluginName}"`)
  }
  checkVersion(extension.version, where)
  requireString(extension, 'description', where)
  checkMcpServer(extension.mcpServers?.pastevault, where)
  const contexts = Array.isArray(extension.contextFileName) ? extension.contextFileName : [extension.contextFileName]
  for (const context of contexts) {
    if (!isNonEmptyString(context) || context.includes('..') || path.isAbsolute(context)) {
      fail(`${where}: contextFileName must be a relative path inside the extension`)
    } else if (!isFile(path.join(base, context))) {
      fail(`${where}: contextFileName ${context} does not exist`)
    }
  }
  for (const [index, setting] of (extension.settings ?? []).entries()) {
    const at = `${where} settings[${index}]`
    requireString(setting, 'name', at)
    requireString(setting, 'description', at)
    if (!/^PASTEVAULT_[A-Z_]+$/.test(setting.envVar ?? '')) {
      fail(`${at}: envVar must be a PASTEVAULT_ variable`)
    }
  }
}
{
  const rootExtension = readJson('gemini-extension.json')
  const pluginExtension = readJson(`${pluginDir}/gemini-extension.json`)
  if (rootExtension && pluginExtension) {
    const strip = (extension) => ({ ...extension, contextFileName: undefined })
    if (JSON.stringify(strip(rootExtension)) !== JSON.stringify(strip(pluginExtension))) {
      fail(`gemini-extension.json and ${pluginDir}/gemini-extension.json must match (except contextFileName)`)
    }
  }
}

// ── the skill ─────────────────────────────────────────────────────────────

function parseFrontmatter(text, where) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text)
  if (!match) {
    fail(`${where}: missing YAML frontmatter`)
    return {}
  }
  // The subset the skill uses: "key: value" and one level of nested
  // "  key: value" under a "key:" line.
  const fields = {}
  let parent = null
  for (const line of match[1].split(/\r?\n/)) {
    if (line.trim() === '' || line.trim().startsWith('#')) {
      continue
    }
    const nested = /^\s+([A-Za-z0-9_-]+):\s*(.*)$/.exec(line)
    const top = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line)
    if (top) {
      parent = top[2] === '' ? top[1] : null
      fields[top[1]] = top[2] === '' ? {} : unquote(top[2])
    } else if (nested && parent) {
      fields[parent][nested[1]] = unquote(nested[2])
    } else {
      fail(`${where}: unsupported frontmatter line ${JSON.stringify(line)}`)
    }
  }
  return fields
}

function unquote(value) {
  const trimmed = value.trim()
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

const skillDir = `${pluginDir}/skills/pastevault`
const skillText = read(`${skillDir}/SKILL.md`)
if (skillText !== null) {
  const where = `${skillDir}/SKILL.md`
  const frontmatter = parseFrontmatter(skillText, where)
  const name = frontmatter.name
  if (typeof name !== 'string' || name.length < 1 || name.length > 64 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) {
    fail(`${where}: name must be 1-64 lowercase letters, digits and single hyphens`)
  } else if (name !== path.basename(skillDir)) {
    fail(`${where}: name "${name}" must match its directory "${path.basename(skillDir)}"`)
  }
  if (typeof frontmatter.description !== 'string' || frontmatter.description.length < 1 || frontmatter.description.length > 1024) {
    fail(`${where}: description must be 1-1024 characters`)
  }
  if (frontmatter.compatibility !== undefined && (typeof frontmatter.compatibility !== 'string' || frontmatter.compatibility.length > 500)) {
    fail(`${where}: compatibility must be at most 500 characters`)
  }
  if (frontmatter.metadata !== undefined && (typeof frontmatter.metadata !== 'object' || Object.values(frontmatter.metadata).some((value) => typeof value !== 'string'))) {
    fail(`${where}: metadata must map strings to strings`)
  }
  const known = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools'])
  for (const key of Object.keys(frontmatter)) {
    if (!known.has(key)) {
      fail(`${where}: unknown frontmatter field "${key}" (Agent Skills spec)`)
    }
  }
}

// ── tool names the docs use exist ─────────────────────────────────────────

const golden = readJson('internal/mcpserver/testdata/tools.golden.json')
if (golden) {
  const tools = new Set(golden.map((tool) => tool.name))
  for (const name of tools) {
    if (name.includes('read')) {
      fail(`tools.golden.json: tool ${name} must not contain "read" (no tool reads secrets)`)
    }
  }
  const toolLike = /`([a-z]+_[a-z_]+)`/g
  const candidates = ['send_text', 'send_file', 'request_secret', 'request_status', 'list_secrets', 'share_status', 'revoke_share', 'read_secret']
  for (const relative of [`${skillDir}/SKILL.md`, `${pluginDir}/GEMINI.md`, 'integrations/AGENTS.snippet.md']) {
    const text = read(relative) ?? ''
    for (const [, word] of text.matchAll(toolLike)) {
      if (candidates.includes(word) && !tools.has(word)) {
        fail(`${relative}: names tool \`${word}\`, which the MCP server does not have`)
      }
    }
    if (!text.includes('request_secret') || !text.includes('pastevault run')) {
      fail(`${relative}: must tell agents to use request_secret and pastevault run`)
    }
  }
}

// ── AGENTS.md and CLAUDE.md ───────────────────────────────────────────────

{
  const body = (text) => (text ?? '').split('\n').slice(3).join('\n')
  const agents = read('AGENTS.md')
  const claude = read('CLAUDE.md')
  if (agents !== null && claude !== null && body(agents) !== body(claude)) {
    fail('AGENTS.md and CLAUDE.md must be identical after their first three lines')
  }
}

// ── version sync ──────────────────────────────────────────────────────────

for (const [where, version] of versions) {
  if (expectedVersion && version !== expectedVersion) {
    fail(`${where}: version ${version} differs from package.json ${expectedVersion}`)
  }
}
if (releaseTag) {
  const tagVersion = releaseTag.replace(/^refs\/tags\//, '').replace(/^v/, '')
  for (const [where, version] of versions) {
    if (version !== tagVersion) {
      fail(`${where}: version ${version} differs from the release tag ${releaseTag}`)
    }
  }
}

if (errors.length > 0) {
  console.error(`check-integrations: ${errors.length} problem(s)`)
  for (const error of errors) {
    console.error(`  - ${error}`)
  }
  process.exit(1)
}
console.log(`check-integrations: OK (${versions.length} manifest versions = ${expectedVersion})`)
