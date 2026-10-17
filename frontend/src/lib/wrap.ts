// PVWRAP1 key wrap (spec §3.2), identical to the Go CLI
// (internal/pastevault/wrap.go). Wraps a share's 32-byte content key to an
// agent's X25519 public key, so a sealed link carries no #k= key:
//
//   e_sk ← random(32); e_pk = X25519(e_sk, 9)
//   ss   = X25519(e_sk, R_pk)                      (abort if all zero)
//   wk   = HKDF-SHA256(ikm=ss, salt=e_pk||R_pk, info="pastevault:wrap:v1", L=32)
//   n    ← random(24)
//   aad  = "pastevault:wrap:v1:" + context + ":" + fingerprint(R_pk)
//   ct   = XChaCha20-Poly1305(wk, n).encrypt(K, aad)  (48 bytes)
//   envelope = 0x01 || e_pk || n || ct               (105 bytes → base64url)
//
// The share's content encryption is unchanged: K is used exactly as with a
// #k= link. Contexts bind an envelope to one object (see wrapContext).
//
// No "@/" imports: this module is also loaded by plain Node (tsx) for the
// crypto vector tests.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { agentFingerprint } from './fingerprint'

export const WRAP_VERSION = 0x01
export const X25519_KEY_BYTES = 32
export const CONTENT_KEY_BYTES = 32
const NONCE_BYTES = 24
const TAG_BYTES = 16
export const WRAP_ENVELOPE_BYTES = 1 + X25519_KEY_BYTES + NONCE_BYTES + CONTENT_KEY_BYTES + TAG_BYTES
const WRAP_INFO = 'pastevault:wrap:v1'
const WRAP_AAD_PREFIX = 'pastevault:wrap:v1:'

// Raised for every wrap/unwrap failure. Unwrap failures (wrong key, wrong
// context, tampering) are deliberately not told apart.
export class WrapError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WrapError'
  }
}

export const wrapContext = {
  paste: (slug: string) => `paste:${slug}`,
  fileShare: (slug: string) => `file-share:${slug}`,
  request: (requestId: string) => `request:${requestId}`,
  store: (name: string) => `store:${name}`,
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Strict: only the canonical unpadded encoding is accepted (no padding bits
// set), so a key or envelope has exactly one text form.
function base64urlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new WrapError('Invalid base64url')
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (base64urlEncode(bytes) !== value) {
    throw new WrapError('Invalid base64url')
  }
  return bytes
}

// The canonical encoding of an X25519 u-coordinate: top bit clear and
// u < p = 2^255 - 19. X25519 would silently reduce anything else, giving one
// key several encodings (and fingerprints).
export function isCanonicalX25519PublicKey(publicKey: Uint8Array): boolean {
  if (publicKey.length !== X25519_KEY_BYTES || (publicKey[31]! & 0x80) !== 0) {
    return false
  }
  if (publicKey[31] !== 0x7f || publicKey[0]! < 0xed) {
    return true
  }
  return publicKey.subarray(1, 31).some((byte) => byte !== 0xff)
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

// X25519 that refuses low-order public keys: noble rejects them, and an
// all-zero result is checked again because it would make the wrap key public.
function sharedSecret(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new WrapError('An X25519 public key must be 32 bytes')
  }
  if (!isCanonicalX25519PublicKey(publicKey)) {
    throw new WrapError('The X25519 public key is not canonically encoded')
  }

  let shared: Uint8Array
  try {
    shared = x25519.getSharedSecret(secretKey, publicKey)
  } catch {
    throw new WrapError('The X25519 public key is a low-order point')
  }
  // Constant-time OR-reduce (noble already throws on this).
  let accumulated = 0
  for (const byte of shared) {
    accumulated |= byte
  }
  if (accumulated === 0) {
    throw new WrapError('The X25519 public key is a low-order point')
  }
  return shared
}

function deriveWrapKey(
  shared: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  context: string
) {
  const wrapKey = hkdf(
    sha256,
    shared,
    concatBytes(ephemeralPublicKey, recipientPublicKey),
    new TextEncoder().encode(WRAP_INFO),
    32
  )
  const aad = new TextEncoder().encode(
    `${WRAP_AAD_PREFIX}${context}:${agentFingerprint(recipientPublicKey)}`
  )
  return { wrapKey, aad }
}

export interface AgentKeyPair {
  secretKey: Uint8Array
  publicKey: Uint8Array
  fingerprint: string
}

export function generateAgentKeyPair(): AgentKeyPair {
  return agentKeyPairFromSecret(crypto.getRandomValues(new Uint8Array(X25519_KEY_BYTES)))
}

export function agentKeyPairFromSecret(secretKey: Uint8Array): AgentKeyPair {
  if (secretKey.length !== X25519_KEY_BYTES) {
    throw new WrapError('An X25519 secret key must be 32 bytes')
  }
  const publicKey = x25519.getPublicKey(secretKey)
  return { secretKey, publicKey, fingerprint: agentFingerprint(publicKey) }
}

// Decodes and validates a base64url public key from the server or a user:
// 32 bytes and not a low-order point.
export function decodeAgentPublicKey(value: string): Uint8Array {
  const publicKey = base64urlDecode(value)
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new WrapError('An X25519 public key must be 32 bytes')
  }
  sharedSecret(crypto.getRandomValues(new Uint8Array(X25519_KEY_BYTES)), publicKey)
  return publicKey
}

// Seals contentKey to recipientPublicKey for one context; returns the
// base64url envelope.
export function wrapKey(
  contentKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  context: string
): string {
  if (contentKey.length !== CONTENT_KEY_BYTES) {
    throw new WrapError('The content key must be 32 bytes')
  }
  if (!context) {
    throw new WrapError('A wrap context is required')
  }

  // Drawn in this order (ephemeral key, then nonce); the vector generator
  // relies on it.
  const ephemeralSecretKey = crypto.getRandomValues(new Uint8Array(X25519_KEY_BYTES))
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))

  const shared = sharedSecret(ephemeralSecretKey, recipientPublicKey)
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey)
  const { wrapKey: key, aad } = deriveWrapKey(shared, ephemeralPublicKey, recipientPublicKey, context)
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(contentKey)

  return base64urlEncode(concatBytes(Uint8Array.of(WRAP_VERSION), ephemeralPublicKey, nonce, ciphertext))
}

// Opens an envelope with the recipient's secret key. The fingerprint in the
// AAD comes from the recipient's own public key.
export function unwrapKey(envelope: string, recipientSecretKey: Uint8Array, context: string): Uint8Array {
  if (!context) {
    throw new WrapError('A wrap context is required')
  }

  let data: Uint8Array
  try {
    data = base64urlDecode(envelope)
  } catch {
    throw new WrapError('The wrapped key could not be opened')
  }
  if (data.length !== WRAP_ENVELOPE_BYTES || data[0] !== WRAP_VERSION) {
    throw new WrapError('The wrapped key could not be opened')
  }

  const ephemeralPublicKey = data.subarray(1, 1 + X25519_KEY_BYTES)
  const nonce = data.subarray(1 + X25519_KEY_BYTES, 1 + X25519_KEY_BYTES + NONCE_BYTES)
  const ciphertext = data.subarray(1 + X25519_KEY_BYTES + NONCE_BYTES)

  try {
    const shared = sharedSecret(recipientSecretKey, ephemeralPublicKey)
    const recipientPublicKey = x25519.getPublicKey(recipientSecretKey)
    const { wrapKey: key, aad } = deriveWrapKey(shared, ephemeralPublicKey, recipientPublicKey, context)
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext)
  } catch {
    throw new WrapError('The wrapped key could not be opened')
  }
}

// The `recipient` field of POST /api/pastes and /api/file-shares: the content
// key sealed to an agent. Pass agentId for an agent of the sender's account
// (the server then requires the recipient to sign in to consume the share).
export interface SealedRecipient {
  agent_id?: string
  fingerprint: string
  wrapped_key: string
}

export function sealToRecipient(
  contentKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  context: string,
  agentId?: string
): SealedRecipient {
  return {
    ...(agentId ? { agent_id: agentId } : {}),
    fingerprint: agentFingerprint(recipientPublicKey),
    wrapped_key: wrapKey(contentKey, recipientPublicKey, context),
  }
}
