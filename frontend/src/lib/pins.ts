// Agent key pins for "share to agent" (spec §4), the browser's counterpart of
// the CLI's known_agents.json. The first share to an agent pins the
// fingerprint recomputed from its public key (trust on first use); later
// shares must see the same key, so a server that swaps an agent's key is
// caught before anything is sealed to it.
//
// Stored per account in localStorage["pv:pins:<userId>"] and keyed by agent
// name, like the CLI: re-initialising an agent under the same name is a key
// change that must be trusted explicitly.
import { AgentSummary } from '@/types'
import { agentFingerprint } from '@/lib/fingerprint'
import { decodeAgentPublicKey } from '@/lib/wrap'

export type PinSource = 'tofu' | 'manual'

export interface AgentPin {
  fingerprint: string
  public_key: string
  first_seen: string
  source: PinSource
}

interface PinStore {
  v: 1
  agents: Record<string, AgentPin>
}

function storageKey(userId: string) {
  return `pv:pins:${userId}`
}

function emptyStore(): PinStore {
  return { v: 1, agents: {} }
}

function readStore(userId: string): PinStore {
  if (typeof window === 'undefined') {
    return emptyStore()
  }

  try {
    const raw = window.localStorage.getItem(storageKey(userId))
    if (!raw) {
      return emptyStore()
    }
    const parsed = JSON.parse(raw) as Partial<PinStore>
    if (parsed?.v !== 1 || typeof parsed.agents !== 'object' || parsed.agents === null) {
      return emptyStore()
    }
    return { v: 1, agents: parsed.agents }
  } catch {
    return emptyStore()
  }
}

export function getPin(userId: string, agentName: string): AgentPin | null {
  const pin = readStore(userId).agents[agentName]
  return pin && typeof pin.fingerprint === 'string' ? pin : null
}

// Returns false when the pin could not be stored (storage full or blocked).
export function savePin(
  userId: string,
  agentName: string,
  fingerprint: string,
  publicKey: string,
  source: PinSource
): boolean {
  const store = readStore(userId)
  store.agents[agentName] = {
    fingerprint,
    public_key: publicKey,
    first_seen: new Date().toISOString(),
    source,
  }

  try {
    window.localStorage.setItem(storageKey(userId), JSON.stringify(store))
    return true
  } catch {
    return false
  }
}

export type AgentKeyCheck =
  // Recomputed fingerprint equals the pin.
  | { state: 'pinned'; fingerprint: string; publicKey: Uint8Array }
  // Nothing pinned yet: pinned after the first successful share.
  | { state: 'unpinned'; fingerprint: string; publicKey: Uint8Array }
  // The key differs from the pinned one. Blocking.
  | { state: 'mismatch'; fingerprint: string; pinnedFingerprint: string; publicKey: Uint8Array }
  // The key is unusable, or doesn't match the fingerprint the server claims
  // for it. Blocking.
  | { state: 'invalid'; fingerprint: string | null }

// Recomputes the agent's fingerprint from its public key and compares it with
// this browser's pin. Never trusts the server's fingerprint field: it is only
// cross-checked, and a disagreement blocks.
export function checkAgentKey(userId: string, agent: AgentSummary): AgentKeyCheck {
  let publicKey: Uint8Array
  let fingerprint: string

  try {
    publicKey = decodeAgentPublicKey(agent.public_key)
    fingerprint = agentFingerprint(publicKey)
  } catch {
    return { state: 'invalid', fingerprint: null }
  }

  const pin = getPin(userId, agent.name)
  if (pin && pin.fingerprint !== fingerprint) {
    return { state: 'mismatch', fingerprint, pinnedFingerprint: pin.fingerprint, publicKey }
  }

  if (agent.fingerprint !== fingerprint) {
    return { state: 'invalid', fingerprint }
  }

  return pin
    ? { state: 'pinned', fingerprint, publicKey }
    : { state: 'unpinned', fingerprint, publicKey }
}

// The fingerprint shown for an agent, recomputed locally; null if the key is
// unusable.
export function localAgentFingerprint(agent: AgentSummary): string | null {
  try {
    return agentFingerprint(decodeAgentPublicKey(agent.public_key))
  } catch {
    return null
  }
}
