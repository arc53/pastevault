// Answers to secret requests (spec §3.3, §6), identical to the Go CLI
// (internal/pastevault/requests.go, SealSecretPayload/OpenSecretPayload):
//
//   plaintext  = UTF-8 JSON {"v":1,"name","kind":"text","value"}
//                        or {"v":1,"name","kind":"file","filename","content_type","data":<b64url>}
//   K ← random(32); n ← random(24)
//   ciphertext = XChaCha20-Poly1305(K, n).encrypt(plaintext, "pastevault:request:<id>:v1")
//   wrapped_key = PVWRAP1(K → request public key, context "request:<id>")
//
// <id> is the request's UUID, not its code. The request key is the agent's
// per-request ephemeral key; its fingerprint is what the URL's #fp= carries.
//
// No "@/" imports: this module is also loaded by plain Node (tsx) for the
// crypto vector tests.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { CONTENT_KEY_BYTES, unwrapKey, wrapContext, wrapKey } from './wrap'

export const SECRET_PAYLOAD_VERSION = 1
const NONCE_BYTES = 24
// Poly1305 tag appended to the ciphertext.
export const SEAL_OVERHEAD_BYTES = 16

export type SecretKind = 'text' | 'file'

// Field order matches the Go struct, so both encoders emit the same bytes.
export type SecretPayload =
  | { v: 1; name: string; kind: 'text'; value: string }
  | { v: 1; name: string; kind: 'file'; filename: string; content_type: string; data: string }

export interface SealedSecret {
  kind: SecretKind
  ciphertext: string
  nonce: string
  wrapped_key: string
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000))
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

export function requestPayloadAAD(requestId: string): string {
  return `pastevault:request:${requestId}:v1`
}

export function textPayload(name: string, value: string): SecretPayload {
  return { v: SECRET_PAYLOAD_VERSION, name, kind: 'text', value }
}

export function filePayload(name: string, filename: string, contentType: string, data: Uint8Array): SecretPayload {
  return {
    v: SECRET_PAYLOAD_VERSION,
    name,
    kind: 'file',
    filename,
    content_type: contentType || 'application/octet-stream',
    data: base64urlEncode(data),
  }
}

export function encodeSecretPayload(payload: SecretPayload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload))
}

// The decoded ciphertext size the server limits (max_bytes): the payload
// JSON plus the tag. Check it before sealing.
export function sealedSize(payload: SecretPayload): number {
  return encodeSecretPayload(payload).length + SEAL_OVERHEAD_BYTES
}

// The largest file whose payload fits max_bytes: base64url costs 4/3, plus
// the JSON around it. Only for display; sealedSize is the real check.
export function maxFileBytes(maxBytes: number, name: string, filename: string, contentType: string): number {
  const envelope = sealedSize(filePayload(name, filename, contentType, new Uint8Array()))
  return Math.max(0, Math.floor(((maxBytes - envelope) * 3) / 4))
}

// Seals a payload to a request's public key (already decoded and checked
// with decodeAgentPublicKey). Draws K (32 bytes), then the nonce (24), then
// wrapKey's ephemeral key and nonce; the vector generator relies on it.
export function sealSecretPayload(
  payload: SecretPayload,
  requestId: string,
  requestPublicKey: Uint8Array
): SealedSecret {
  const contentKey = crypto.getRandomValues(new Uint8Array(CONTENT_KEY_BYTES))
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const aad = new TextEncoder().encode(requestPayloadAAD(requestId))
  const ciphertext = xchacha20poly1305(contentKey, nonce, aad).encrypt(encodeSecretPayload(payload))
  const wrappedKey = wrapKey(contentKey, requestPublicKey, wrapContext.request(requestId))
  contentKey.fill(0)

  return {
    kind: payload.kind,
    ciphertext: base64urlEncode(ciphertext),
    nonce: base64urlEncode(nonce),
    wrapped_key: wrappedKey,
  }
}

// The agent side, for tests: unwraps with the request's secret key and
// decrypts. Throws on any mismatch.
export function openSecretPayload(
  sealed: Pick<SealedSecret, 'ciphertext' | 'nonce' | 'wrapped_key'>,
  requestSecretKey: Uint8Array,
  requestId: string
): SecretPayload {
  const contentKey = unwrapKey(sealed.wrapped_key, requestSecretKey, wrapContext.request(requestId))
  const aad = new TextEncoder().encode(requestPayloadAAD(requestId))
  const plaintext = xchacha20poly1305(contentKey, base64urlDecode(sealed.nonce), aad).decrypt(
    base64urlDecode(sealed.ciphertext)
  )
  return JSON.parse(new TextDecoder().decode(plaintext)) as SecretPayload
}
