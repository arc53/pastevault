#!/usr/bin/env node
// Generates testdata/crypto/vectors.json from the web app's own crypto code
// (frontend/src/lib/crypto.ts and file-shares.ts), so other implementations
// (the Go CLI: internal/pastevault/*_test.go) can prove they produce and read
// exactly the same bytes.
//
//   node scripts/crypto-vectors.mjs           rewrite the file
//   node scripts/crypto-vectors.mjs --check   fail if the file is out of date
//
// Randomness is replaced by fixed inputs: crypto.getRandomValues is stubbed
// to hand out queued byte strings, and every call must consume exactly the
// queued value, so a change in how the frontend draws keys, salts or nonces
// fails loudly instead of silently changing the vectors.
//
// Adding a section: write a `async function xxxVectors(lib)` returning an
// array of vectors and add it to SECTIONS. Keep inputs deterministic.
import assert from 'node:assert/strict'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { importFrontend } from './lib/frontend-modules.mjs'

const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const vectorsPath = path.join(projectRoot, 'testdata', 'crypto', 'vectors.json')

const randomQueue = []
Object.defineProperty(globalThis.crypto, 'getRandomValues', {
  configurable: true,
  value(target) {
    const next = randomQueue.shift()
    assert(next, 'the frontend drew more random bytes than the vector supplies')
    assert.equal(target.length, next.length, 'the frontend drew a different number of random bytes')
    target.set(next)
    return target
  },
})

async function withRandom(values, fn) {
  randomQueue.length = 0
  randomQueue.push(...values)
  const result = await fn()
  assert.equal(randomQueue.length, 0, 'the frontend drew fewer random bytes than the vector supplies')
  return result
}

function bytes(length, start) {
  return Uint8Array.from({ length }, (_, index) => (start + index * 7) & 0xff)
}

const b64url = (data) => Buffer.from(data).toString('base64url')

async function pasteVectors({ crypto }) {
  const urlKeyCases = [
    {
      name: 'paste-url-key-plain-language',
      slug: 'Vb3kq9TQx_2Z',
      content: {
        title: 'deploy notes',
        body: 'line 1\nline 2 with "quotes", a \\ backslash & <tags>\n',
        render_mode: 'plain',
        language_hint: 'bash',
      },
    },
    {
      name: 'paste-url-key-markdown-unicode',
      slug: 'mD-unic0de42',
      content: {
        title: '',
        body: '# Héllo 👋\n\n- ünïcödé\n- tab\there\n',
        render_mode: 'markdown',
      },
    },
  ]

  const vectors = []
  for (const [index, testCase] of urlKeyCases.entries()) {
    const key = bytes(32, 1 + index)
    const nonce = bytes(24, 0x40 + index)
    const encrypted = await withRandom([key, nonce], () =>
      crypto.encryptPaste(testCase.content, testCase.slug)
    )
    const decrypted = await crypto.decryptPaste(encrypted.ciphertext, encrypted.nonce, key, testCase.slug)
    assert.deepEqual(decrypted, testCase.content)

    vectors.push({
      name: testCase.name,
      mode: 'url_key',
      slug: testCase.slug,
      aad: `pastevault:${testCase.slug}:v1`,
      content: testCase.content,
      plaintext: JSON.stringify(testCase.content),
      key: b64url(key),
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext,
    })
  }

  const password = 'correct horse battery staple'
  const salt = bytes(16, 0x90)
  const nonce = bytes(24, 0x60)
  const slug = 'pW-protected'
  const content = {
    title: '.env',
    body: 'API_KEY=sk-test-123\nDATABASE_URL=postgres://u:p@db/app\n',
    render_mode: 'plain',
    language_hint: 'bash',
  }
  const encrypted = await withRandom([salt, nonce], () =>
    crypto.encryptPasteWithPassword(content, password, slug)
  )
  const { key } = await crypto.deriveKeyFromPassword(password, salt)
  const decrypted = await crypto.decryptPasteWithPassword(
    encrypted.ciphertext,
    encrypted.nonce,
    encrypted.salt,
    encrypted.kdf_params,
    password,
    slug
  )
  assert.deepEqual(decrypted, content)

  vectors.push({
    name: 'paste-password',
    mode: 'password',
    slug,
    aad: `pastevault:${slug}:v1`,
    content,
    plaintext: JSON.stringify(content),
    password,
    salt: encrypted.salt,
    kdf_params: encrypted.kdf_params,
    key: b64url(key),
    nonce: encrypted.nonce,
    ciphertext: encrypted.ciphertext,
  })

  return vectors
}

async function chunkVectors({ fileShares }) {
  const cases = [
    { name: 'chunk-text', slug: 'fileslug1234', fileId: 'file_id_0001', index: 0, plaintext: Buffer.from('hello chunk\n') },
    { name: 'chunk-binary-index-3', slug: 'fileslug1234', fileId: 'file_id_0002', index: 3, plaintext: Buffer.from(bytes(64, 0xf0)) },
  ]

  const vectors = []
  for (const [index, testCase] of cases.entries()) {
    const key = bytes(32, 0x20 + index)
    const nonce = bytes(24, 0x30 + index)
    const encrypted = await withRandom([nonce], () =>
      fileShares.encryptFileChunk(new Uint8Array(testCase.plaintext), key, testCase.slug, testCase.fileId, testCase.index)
    )
    const decrypted = fileShares.decryptFileChunk(
      encrypted.ciphertext,
      encrypted.nonce,
      key,
      testCase.slug,
      testCase.fileId,
      testCase.index
    )
    assert.deepEqual(Buffer.from(decrypted), testCase.plaintext)

    vectors.push({
      name: testCase.name,
      slug: testCase.slug,
      file_id: testCase.fileId,
      index: testCase.index,
      aad: `pastevault:file-share:chunk:${testCase.slug}:${testCase.fileId}:${testCase.index}:v1`,
      key: b64url(key),
      nonce: encrypted.nonce,
      plaintext: b64url(testCase.plaintext),
      ciphertext: b64url(encrypted.ciphertext),
    })
  }

  return vectors
}

async function manifestVectors({ fileShares }) {
  const slug = 'fileslug1234'
  // Field order follows the Go CLI's manifest struct, so Go can re-encrypt
  // the same plaintext byte for byte; the web reads either order.
  const manifest = {
    version: 'v1',
    paste: { title: 'Read me', body: 'Two files attached.', render_mode: 'plain' },
    files: [
      {
        id: 'file_id_0001',
        name: 'notes.txt',
        size: 12,
        type: 'text/plain',
        last_modified: 1760000000000,
        chunks: [{ index: 0, nonce: b64url(bytes(24, 0x30)), plaintext_size: 12 }],
      },
    ],
  }
  const key = bytes(32, 0x50)
  const nonce = bytes(24, 0x70)
  const encrypted = await withRandom([nonce], () => fileShares.encryptFileShareManifest(manifest, key, slug))
  assert.deepEqual(
    fileShares.decryptFileShareManifest(encrypted.manifest_ciphertext, encrypted.manifest_nonce, key, slug),
    manifest
  )

  return [
    {
      name: 'manifest-with-note',
      slug,
      aad: `pastevault:file-share:manifest:${slug}:v1`,
      manifest,
      plaintext: JSON.stringify(manifest),
      key: b64url(key),
      nonce: encrypted.manifest_nonce,
      ciphertext: encrypted.manifest_ciphertext,
    },
  ]
}

const SECTIONS = [
  ['paste', pasteVectors],
  ['chunk', chunkVectors],
  ['manifest', manifestVectors],
]

async function generate() {
  const lib = {
    crypto: await importFrontend('lib/crypto.ts'),
    fileShares: await importFrontend('lib/file-shares.ts'),
  }

  const document = {
    description:
      'PasteVault crypto test vectors, generated from the web app by scripts/crypto-vectors.mjs. Do not edit by hand.',
    version: 1,
  }
  for (const [name, build] of SECTIONS) {
    document[name] = await build(lib)
  }

  return `${JSON.stringify(document, null, 2)}\n`
}

const generated = await generate()

if (process.argv.includes('--check')) {
  const current = existsSync(vectorsPath) ? readFileSync(vectorsPath, 'utf8') : ''
  if (current !== generated) {
    console.error(`${path.relative(projectRoot, vectorsPath)} is out of date; run node scripts/crypto-vectors.mjs`)
    process.exit(1)
  }
  console.log(`${path.relative(projectRoot, vectorsPath)} matches the frontend implementation`)
} else {
  mkdirSync(path.dirname(vectorsPath), { recursive: true })
  writeFileSync(vectorsPath, generated)
  console.log(`Wrote ${path.relative(projectRoot, vectorsPath)}`)
}
