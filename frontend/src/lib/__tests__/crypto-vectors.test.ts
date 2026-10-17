// Checks the web's agent-key crypto (fingerprint.ts, wrap.ts) against
// testdata/crypto/vectors.json, which the Go CLI checks too. Run from the
// repository root with `npm run test:crypto`, or directly:
//   npx tsx --test frontend/src/lib/__tests__/crypto-vectors.test.ts
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  agentFingerprint,
  formatFingerprint,
  isFingerprint,
  shortFingerprint,
} from '../fingerprint'
import {
  agentKeyPairFromSecret,
  decodeAgentPublicKey,
  generateAgentKeyPair,
  isCanonicalX25519PublicKey,
  sealToRecipient,
  unwrapKey,
  wrapContext,
  WrapError,
  wrapKey,
} from '../wrap'
import {
  openSecretPayload,
  requestPayloadAAD,
  sealedSize,
  sealSecretPayload,
  SecretPayload,
} from '../secret-requests'

interface FingerprintVector {
  name: string
  secret_key?: string
  public_key: string
  fingerprint: string
  short: string
  display: string
}

interface WrapVector {
  name: string
  context: string
  content_key: string
  recipient_secret_key: string
  recipient_public_key: string
  recipient_fingerprint: string
  ephemeral_secret_key: string
  nonce: string
  envelope: string
}

interface WrapNegativeVector {
  name: string
  operation: 'wrap' | 'unwrap'
  reason: string
  envelope?: string
  recipient_secret_key?: string
  recipient_public_key?: string
  content_key?: string
  context: string
}

interface RequestPayloadVector {
  name: string
  request_id: string
  request_secret_key: string
  request_public_key: string
  request_fingerprint: string
  aad: string
  wrap_context: string
  payload: SecretPayload
  plaintext: string
  kind: string
  content_key: string
  nonce: string
  ephemeral_secret_key: string
  wrap_nonce: string
  ciphertext: string
  wrapped_key: string
}

const vectors = JSON.parse(
  readFileSync(new URL('../../../../testdata/crypto/vectors.json', import.meta.url), 'utf8')
) as {
  fingerprint: FingerprintVector[]
  wrap: WrapVector[]
  wrap_negative: WrapNegativeVector[]
  request_payload: RequestPayloadVector[]
}

const decode = (value: string) => new Uint8Array(Buffer.from(value, 'base64url'))

// Replays fixed randomness into wrapKey. @noble/curves' own blinding draws
// (they never change results) still get real randomness.
function withRandom<T>(values: Uint8Array[], fn: () => T): T {
  const original = globalThis.crypto.getRandomValues
  const queue = [...values]
  Object.defineProperty(globalThis.crypto, 'getRandomValues', {
    configurable: true,
    value(target: Uint8Array): Uint8Array {
      if (new Error().stack?.includes('/@noble/curves/')) {
        return original.call(globalThis.crypto, target) as Uint8Array
      }
      const next = queue.shift()
      assert(next && target instanceof Uint8Array && target.length === next.length, 'unexpected random draw')
      target.set(next)
      return target
    },
  })
  try {
    const result = fn()
    assert.equal(queue.length, 0, 'fewer random draws than expected')
    return result
  } finally {
    Object.defineProperty(globalThis.crypto, 'getRandomValues', { configurable: true, value: original })
  }
}

test('vectors file has agent-key sections', () => {
  assert(vectors.fingerprint.length > 0)
  assert(vectors.wrap.length > 0)
  assert(vectors.wrap_negative.length > 0)
  assert(vectors.request_payload.length > 0)
})

for (const vector of vectors.fingerprint) {
  test(`fingerprint: ${vector.name}`, () => {
    const publicKey = decode(vector.public_key)
    if (vector.secret_key) {
      const pair = agentKeyPairFromSecret(decode(vector.secret_key))
      assert.equal(Buffer.from(pair.publicKey).toString('base64url'), vector.public_key)
      assert.equal(pair.fingerprint, vector.fingerprint)
    }
    assert.equal(agentFingerprint(publicKey), vector.fingerprint)
    assert(isFingerprint(vector.fingerprint))
    assert.equal(shortFingerprint(vector.fingerprint), vector.short)
    assert.equal(formatFingerprint(vector.fingerprint), vector.display)
  })
}

for (const vector of vectors.wrap) {
  test(`wrap: ${vector.name}`, () => {
    const contentKey = decode(vector.content_key)
    const recipientPublicKey = decode(vector.recipient_public_key)
    assert.equal(agentFingerprint(recipientPublicKey), vector.recipient_fingerprint)

    const envelope = withRandom([decode(vector.ephemeral_secret_key), decode(vector.nonce)], () =>
      wrapKey(contentKey, recipientPublicKey, vector.context)
    )
    assert.equal(envelope, vector.envelope)
    assert.deepEqual(unwrapKey(vector.envelope, decode(vector.recipient_secret_key), vector.context), contentKey)
  })
}

for (const vector of vectors.wrap_negative) {
  test(`wrap negative: ${vector.name}`, () => {
    if (vector.operation === 'unwrap') {
      assert.throws(
        () => unwrapKey(vector.envelope!, decode(vector.recipient_secret_key!), vector.context),
        WrapError,
        vector.reason
      )
    } else {
      assert.throws(
        () => wrapKey(decode(vector.content_key!), decode(vector.recipient_public_key!), vector.context),
        WrapError,
        vector.reason
      )
      assert.throws(() => decodeAgentPublicKey(vector.recipient_public_key!), WrapError)
    }
  })
}

test('wrap round trip with fresh keys, and the share recipient payload', () => {
  const recipient = generateAgentKeyPair()
  const contentKey = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const context = wrapContext.fileShare('slug-123')

  const sealed = sealToRecipient(contentKey, recipient.publicKey, context, 'agent-id')
  assert.equal(sealed.agent_id, 'agent-id')
  assert.equal(sealed.fingerprint, recipient.fingerprint)
  assert.match(sealed.wrapped_key, /^[A-Za-z0-9_-]{140}$/)
  assert.deepEqual(unwrapKey(sealed.wrapped_key, recipient.secretKey, context), contentKey)
  assert.throws(() => unwrapKey(sealed.wrapped_key, recipient.secretKey, wrapContext.paste('slug-123')), WrapError)
  assert.equal(
    Buffer.from(decodeAgentPublicKey(Buffer.from(recipient.publicKey).toString('base64url'))).toString('hex'),
    Buffer.from(recipient.publicKey).toString('hex')
  )
  assert.throws(() => decodeAgentPublicKey('AAAA'), WrapError)
})

test('low-order public keys are refused (libsodium blocklist)', () => {
  const contentKey = new Uint8Array(32).fill(7)
  for (const point of [
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ]) {
    const publicKey = new Uint8Array(Buffer.from(point, 'hex'))
    assert.throws(() => wrapKey(contentKey, publicKey, wrapContext.paste('x')), WrapError, point)
    assert.throws(() => decodeAgentPublicKey(Buffer.from(publicKey).toString('base64url')), WrapError, point)
  }
})

test('non-canonical keys and base64url are refused', () => {
  const recipient = generateAgentKeyPair()
  const topBit = Uint8Array.from(recipient.publicKey)
  topBit[31]! |= 0x80
  const basePointPlusP = new Uint8Array(Buffer.from('f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'))
  for (const publicKey of [topBit, basePointPlusP]) {
    assert.equal(isCanonicalX25519PublicKey(publicKey), false)
    assert.throws(() => wrapKey(new Uint8Array(32), publicKey, wrapContext.paste('x')), WrapError)
  }
  assert.equal(isCanonicalX25519PublicKey(recipient.publicKey), true)

  // The last character of a 32-byte key carries 2 padding bits; setting one
  // gives another string for the same bytes, which must be refused.
  const encoded = Buffer.from(recipient.publicKey).toString('base64url')
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const last = alphabet.indexOf(encoded[encoded.length - 1]!)
  const mangled = encoded.slice(0, -1) + alphabet[last + 1]
  assert.throws(() => decodeAgentPublicKey(mangled), WrapError)
})

for (const vector of vectors.request_payload) {
  test(`request payload: ${vector.name}`, () => {
    const publicKey = decodeAgentPublicKey(vector.request_public_key)
    assert.equal(agentFingerprint(publicKey), vector.request_fingerprint)
    assert.equal(requestPayloadAAD(vector.request_id), vector.aad)
    assert.equal(wrapContext.request(vector.request_id), vector.wrap_context)
    assert.equal(JSON.stringify(vector.payload), vector.plaintext)

    const sealed = withRandom(
      [decode(vector.content_key), decode(vector.nonce), decode(vector.ephemeral_secret_key), decode(vector.wrap_nonce)],
      () => sealSecretPayload(vector.payload, vector.request_id, publicKey)
    )
    assert.deepEqual(sealed, {
      kind: vector.kind,
      ciphertext: vector.ciphertext,
      nonce: vector.nonce,
      wrapped_key: vector.wrapped_key,
    })
    assert.equal(sealedSize(vector.payload), decode(vector.ciphertext).length)

    const secretKey = decode(vector.request_secret_key)
    assert.deepEqual(openSecretPayload(sealed, secretKey, vector.request_id), vector.payload)
    assert.throws(() => openSecretPayload(sealed, secretKey, '00000000-0000-4000-8000-000000000000'))
  })
}
