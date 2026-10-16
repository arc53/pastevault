import { agentFingerprint, isFingerprint } from '@/lib/fingerprint'
import { decodeAgentPublicKey } from '@/lib/wrap'

// The request key's fingerprint is recomputed from its public key and
// compared with the #fp= the agent put in the link (spec §6). The server's
// own `fingerprint` field is never trusted for this.
export type RequestKeyCheck =
  // Matches #fp=: safe to answer.
  | { state: 'verified'; fingerprint: string; publicKey: Uint8Array }
  // No #fp= (code typed by hand, or the account's list): compare by eye.
  | { state: 'unverified'; fingerprint: string; publicKey: Uint8Array }
  // #fp= differs or is malformed. Blocking.
  | { state: 'mismatch'; fingerprint: string; expected: string }
  // The key is unusable, or differs from the server's own record. Blocking.
  | { state: 'invalid' }

// "#fp=pvk1_…" → the value (an empty "#fp=" gives ""); undefined when the
// link has no fp at all.
export function readLinkFingerprint(): string | undefined {
  if (typeof window === 'undefined') {
    return undefined
  }
  const fragment = window.location.hash.replace(/^#/, '')
  const params = new URLSearchParams(fragment)
  return params.has('fp') ? (params.get('fp') ?? '') : undefined
}

// A present but empty or malformed #fp= is a mismatch (blocking), never
// "no fingerprint".
export function checkRequestKey(
  publicKey: string,
  serverFingerprint: string,
  linkFingerprint: string | undefined
): RequestKeyCheck {
  let decoded: Uint8Array
  let fingerprint: string
  try {
    decoded = decodeAgentPublicKey(publicKey)
    fingerprint = agentFingerprint(decoded)
  } catch {
    return { state: 'invalid' }
  }

  if (linkFingerprint !== undefined) {
    if (!isFingerprint(linkFingerprint) || linkFingerprint !== fingerprint) {
      return { state: 'mismatch', fingerprint, expected: linkFingerprint }
    }
    return { state: 'verified', fingerprint, publicKey: decoded }
  }

  if (serverFingerprint !== fingerprint) {
    return { state: 'invalid' }
  }
  return { state: 'unverified', fingerprint, publicKey: decoded }
}

// "1:05:09" / "4:07"; 0 when expired.
export function formatCountdown(milliseconds: number): string {
  const total = Math.max(0, Math.floor(milliseconds / 1000))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const seconds = String(total % 60).padStart(2, '0')
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, '0')}:${seconds}` : `${minutes}:${seconds}`
}
