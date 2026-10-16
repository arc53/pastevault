#!/usr/bin/env node
// Generates testdata/crypto/vectors.json from the web app's own crypto code
// (frontend/src/lib/crypto.ts, file-shares.ts, fingerprint.ts and wrap.ts), so other implementations
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
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { importFrontend } from './lib/frontend-modules.mjs'

const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const vectorsPath = path.join(projectRoot, 'testdata', 'crypto', 'vectors.json')

const randomQueue = []
const realGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto)
Object.defineProperty(globalThis.crypto, 'getRandomValues', {
  configurable: true,
  value(target) {
    // @noble/curves draws its own randomness to blind scalar multiplications
    // (side-channel hardening). It never changes a result, so it is served by
    // the real RNG instead of the queue.
    if (new Error().stack?.includes('/@noble/curves/')) {
      return realGetRandomValues(target)
    }
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

async function fingerprintVectors({ fingerprint }) {
  const cases = [
    { name: 'fingerprint-from-secret-a', secretKey: bytes(32, 0xa0) },
    { name: 'fingerprint-from-secret-b', secretKey: bytes(32, 0x11) },
    // The X25519 base point (u = 9) as a plain public key.
    { name: 'fingerprint-base-point', publicKey: Uint8Array.from({ length: 32 }, (_, index) => (index === 0 ? 9 : 0)) },
  ]

  return cases.map((testCase) => {
    const publicKey = testCase.publicKey ?? x25519.getPublicKey(testCase.secretKey)
    const value = fingerprint.agentFingerprint(publicKey)
    assert.match(value, /^pvk1_[a-z2-7]{32}$/)

    // Independent check of the construction itself.
    const digest = sha256(
      Buffer.concat([Buffer.from('pastevault:agent-key:v1'), Buffer.from([0]), Buffer.from(publicKey)])
    )
    assert.equal(value.slice(5), base32(digest.subarray(0, 20)))

    return {
      name: testCase.name,
      ...(testCase.secretKey ? { secret_key: b64url(testCase.secretKey) } : {}),
      public_key: b64url(publicKey),
      fingerprint: value,
      short: fingerprint.shortFingerprint(value),
      display: fingerprint.formatFingerprint(value),
    }
  })
}

function base32(data) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  let bits = ''
  for (const byte of data) bits += byte.toString(2).padStart(8, '0')
  let output = ''
  for (let index = 0; index + 5 <= bits.length; index += 5) {
    output += alphabet[parseInt(bits.slice(index, index + 5), 2)]
  }
  return output
}

// PVWRAP1 rebuilt from the primitives, with any fingerprint in the AAD. Used
// to cross-check wrap.ts and to build the wrong-fingerprint negative case.
function manualWrap({ contentKey, recipientPublicKey, aadFingerprint, context, ephemeralSecretKey, nonce }) {
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey)
  const shared = x25519.getSharedSecret(ephemeralSecretKey, recipientPublicKey)
  const wrapKey = hkdf(
    sha256,
    shared,
    Buffer.concat([ephemeralPublicKey, recipientPublicKey]),
    Buffer.from('pastevault:wrap:v1'),
    32
  )
  const aad = `pastevault:wrap:v1:${context}:${aadFingerprint}`
  const ciphertext = xchacha20poly1305(wrapKey, nonce, Buffer.from(aad)).encrypt(contentKey)
  return {
    ephemeralPublicKey,
    shared,
    wrapKey,
    aad,
    envelope: b64url(Buffer.concat([Buffer.from([1]), ephemeralPublicKey, nonce, ciphertext])),
  }
}

const WRAP_CASES = [
  { name: 'wrap-paste', context: 'paste:Vb3kq9TQx_2Z', contentKey: bytes(32, 0x01), recipientSecretKey: bytes(32, 0xa0), ephemeralSecretKey: bytes(32, 0xc3), nonce: bytes(24, 0x5a) },
  { name: 'wrap-file-share', context: 'file-share:fileslug1234', contentKey: bytes(32, 0x20), recipientSecretKey: bytes(32, 0x11), ephemeralSecretKey: bytes(32, 0x77), nonce: bytes(24, 0x05) },
]

async function wrapVectors({ wrap, fingerprint }) {
  const vectors = []
  for (const testCase of WRAP_CASES) {
    const recipientPublicKey = x25519.getPublicKey(testCase.recipientSecretKey)
    const recipientFingerprint = fingerprint.agentFingerprint(recipientPublicKey)
    const envelope = await withRandom([testCase.ephemeralSecretKey, testCase.nonce], () =>
      wrap.wrapKey(testCase.contentKey, recipientPublicKey, testCase.context)
    )
    const manual = manualWrap({ ...testCase, recipientPublicKey, aadFingerprint: recipientFingerprint })
    assert.equal(envelope, manual.envelope, 'wrap.ts matches the construction in the spec')
    assert.equal(Buffer.from(envelope, 'base64url').length, 105)
    assert.equal(envelope.length, 140)
    assert.deepEqual(wrap.unwrapKey(envelope, testCase.recipientSecretKey, testCase.context), testCase.contentKey)

    vectors.push({
      name: testCase.name,
      context: testCase.context,
      content_key: b64url(testCase.contentKey),
      recipient_secret_key: b64url(testCase.recipientSecretKey),
      recipient_public_key: b64url(recipientPublicKey),
      recipient_fingerprint: recipientFingerprint,
      ephemeral_secret_key: b64url(testCase.ephemeralSecretKey),
      ephemeral_public_key: b64url(manual.ephemeralPublicKey),
      nonce: b64url(testCase.nonce),
      shared_secret: b64url(manual.shared),
      wrap_key: b64url(manual.wrapKey),
      aad: manual.aad,
      envelope,
    })
  }

  return vectors
}

// Every case must fail: unwrap cases with the given secret key and context,
// wrap cases (operation "wrap") because the recipient key is unusable.
async function wrapNegativeVectors({ wrap, fingerprint }) {
  const base = WRAP_CASES[0]
  const recipientPublicKey = x25519.getPublicKey(base.recipientSecretKey)
  const envelope = await withRandom([base.ephemeralSecretKey, base.nonce], () =>
    wrap.wrapKey(base.contentKey, recipientPublicKey, base.context)
  )
  const raw = Buffer.from(envelope, 'base64url')
  const tampered = Buffer.from(raw)
  tampered[tampered.length - 1] ^= 0x01
  const badVersion = Buffer.from(raw)
  badVersion[0] = 0x02
  const zeroEphemeral = Buffer.from(raw)
  zeroEphemeral.fill(0, 1, 33)

  const otherPublicKey = x25519.getPublicKey(WRAP_CASES[1].recipientSecretKey)
  const wrongFingerprint = manualWrap({
    ...base,
    recipientPublicKey,
    aadFingerprint: fingerprint.agentFingerprint(otherPublicKey),
  }).envelope

  // Low-order points: u = 0, and a point of order 8.
  const zeroPoint = new Uint8Array(32)
  const orderEightPoint = Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex')

  const unwrapCase = (name, reason, value, secretKey = base.recipientSecretKey, context = base.context) => ({
    name,
    operation: 'unwrap',
    reason,
    envelope: value,
    recipient_secret_key: b64url(secretKey),
    context,
  })
  const wrapCase = (name, reason, publicKey) => ({
    name,
    operation: 'wrap',
    reason,
    recipient_public_key: b64url(publicKey),
    content_key: b64url(base.contentKey),
    context: base.context,
  })

  const vectors = [
    unwrapCase('unwrap-wrong-context', 'the envelope was made for another paste', envelope, base.recipientSecretKey, 'paste:another-slug'),
    unwrapCase('unwrap-wrong-context-kind', 'a paste envelope used for a file share with the same slug', envelope, base.recipientSecretKey, 'file-share:Vb3kq9TQx_2Z'),
    unwrapCase('unwrap-wrong-recipient', 'opened with another agent key', envelope, WRAP_CASES[1].recipientSecretKey),
    unwrapCase('unwrap-wrong-fingerprint', 'the AAD binds another recipient fingerprint', wrongFingerprint),
    unwrapCase('unwrap-tampered', 'one ciphertext bit flipped', b64url(tampered)),
    unwrapCase('unwrap-bad-version', 'unknown envelope version byte', b64url(badVersion)),
    unwrapCase('unwrap-truncated', 'envelope shorter than 105 bytes', b64url(raw.subarray(0, 104))),
    unwrapCase('unwrap-zero-ephemeral', 'low-order ephemeral key gives an all-zero shared secret', b64url(zeroEphemeral)),
    wrapCase('wrap-zero-public-key', 'all-zero shared secret', zeroPoint),
    wrapCase('wrap-low-order-public-key', 'point of order 8 gives an all-zero shared secret', orderEightPoint),
  ]

  for (const vector of vectors) {
    if (vector.operation === 'unwrap') {
      assert.throws(
        () => wrap.unwrapKey(vector.envelope, Buffer.from(vector.recipient_secret_key, 'base64url'), vector.context),
        wrap.WrapError,
        vector.name
      )
    } else {
      await withRandom([base.ephemeralSecretKey, base.nonce], () =>
        assert.throws(
          () => wrap.wrapKey(base.contentKey, Buffer.from(vector.recipient_public_key, 'base64url'), vector.context),
          wrap.WrapError,
          vector.name
        )
      )
    }
  }

  return vectors
}

const SECTIONS = [
  ['paste', pasteVectors],
  ['chunk', chunkVectors],
  ['manifest', manifestVectors],
  ['fingerprint', fingerprintVectors],
  ['wrap', wrapVectors],
  ['wrap_negative', wrapNegativeVectors],
]

async function generate() {
  const lib = {
    crypto: await importFrontend('lib/crypto.ts'),
    fileShares: await importFrontend('lib/file-shares.ts'),
    fingerprint: await importFrontend('lib/fingerprint.ts'),
    wrap: await importFrontend('lib/wrap.ts'),
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
