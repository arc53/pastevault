// Agent key fingerprints (spec §3.1), identical to the Go CLI
// (internal/pastevault/fingerprint.go):
//
//   digest = SHA-256("pastevault:agent-key:v1" || 0x00 || publicKey[32])
//   fp     = "pvk1_" + base32_lower_nopad(digest[0:20])
//
// Always compute fingerprints from public keys; never trust a fingerprint
// string from the server. Compare full strings, never the short form.
//
// No "@/" imports: this module is also loaded by plain Node (tsx) for the
// crypto vector tests.
import { sha256 } from '@noble/hashes/sha2.js'

export const FINGERPRINT_PREFIX = 'pvk1_'
export const SHORT_FINGERPRINT_CHARS = 8

const FINGERPRINT_DOMAIN = 'pastevault:agent-key:v1'
const FINGERPRINT_PATTERN = /^pvk1_[a-z2-7]{32}$/
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

function base32LowerNoPad(bytes: Uint8Array): string {
  let output = ''
  let buffer = 0
  let bits = 0

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
    buffer &= (1 << bits) - 1
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]
  }

  return output
}

export function agentFingerprint(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error('An agent public key must be 32 bytes')
  }

  const domain = new TextEncoder().encode(FINGERPRINT_DOMAIN)
  const input = new Uint8Array(domain.length + 1 + publicKey.length)
  input.set(domain, 0)
  input[domain.length] = 0
  input.set(publicKey, domain.length + 1)

  return FINGERPRINT_PREFIX + base32LowerNoPad(sha256(input).subarray(0, 20))
}

export function isFingerprint(value: string): boolean {
  return FINGERPRINT_PATTERN.test(value)
}

// Display only: "pvk1_" plus the first eight characters.
export function shortFingerprint(fingerprint: string): string {
  if (!fingerprint.startsWith(FINGERPRINT_PREFIX)) {
    return fingerprint
  }

  return fingerprint.slice(0, FINGERPRINT_PREFIX.length + SHORT_FINGERPRINT_CHARS)
}

// "pvk1_abcd 2345 …": groups of four for comparing by eye.
export function formatFingerprint(fingerprint: string): string {
  if (!fingerprint.startsWith(FINGERPRINT_PREFIX)) {
    return fingerprint
  }

  const body = fingerprint.slice(FINGERPRINT_PREFIX.length)
  return FINGERPRINT_PREFIX + (body.match(/.{1,4}/g) ?? []).join(' ')
}
