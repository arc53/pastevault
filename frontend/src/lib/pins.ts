// Agent key pins for "share to agent" (spec §4), the browser's counterpart of
// the CLI's known_agents.json. The first share to an agent pins the
// fingerprint recomputed from its public key (trust on first use); later
// shares must see the same key, so a server that swaps an agent's key is
// caught before anything is sealed to it.
//
// One store per origin, localStorage["pv:pins"], holding entries tagged with
// the agent id, the agent name and the account (user id). Lookups match by
// agent id OR name across every account: the user id comes from the server,
// so a server that also changes it must not make a swapped key look like a
// first use. The account is kept for display and replacement only.
//
// Older builds stored localStorage["pv:pins:<userId>"] = {v:1, agents:{name:
// pin}}; those are migrated on first read.
import { AgentSummary } from '@/types'
import { agentFingerprint } from '@/lib/fingerprint'
import { decodeAgentPublicKey } from '@/lib/wrap'

export type PinSource = 'tofu' | 'manual'

export interface AgentPin {
  agent_id: string | null
  name: string
  user_id: string
  fingerprint: string
  public_key: string
  first_seen: string
  source: PinSource
}

interface PinStore {
  v: 2
  pins: AgentPin[]
}

const STORE_KEY = 'pv:pins'
const LEGACY_PREFIX = 'pv:pins:'

function emptyStore(): PinStore {
  return { v: 2, pins: [] }
}

function isPin(value: unknown): value is AgentPin {
  const pin = value as AgentPin
  return Boolean(pin) && typeof pin.name === 'string' && typeof pin.fingerprint === 'string'
}

function writeStore(store: PinStore): boolean {
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(store))
    return true
  } catch {
    return false
  }
}

// Folds legacy per-user stores into the origin store and removes them.
function migrateLegacy(store: PinStore): boolean {
  let changed = false
  for (let index = window.localStorage.length - 1; index >= 0; index--) {
    const key = window.localStorage.key(index)
    if (!key || !key.startsWith(LEGACY_PREFIX)) {
      continue
    }
    try {
      const legacy = JSON.parse(window.localStorage.getItem(key) ?? 'null') as {
        v?: number
        agents?: Record<string, { fingerprint?: string; public_key?: string; first_seen?: string; source?: PinSource }>
      } | null
      for (const [name, pin] of Object.entries(legacy?.agents ?? {})) {
        if (typeof pin?.fingerprint !== 'string') {
          continue
        }
        store.pins.push({
          agent_id: null,
          name,
          user_id: key.slice(LEGACY_PREFIX.length),
          fingerprint: pin.fingerprint,
          public_key: pin.public_key ?? '',
          first_seen: pin.first_seen ?? new Date().toISOString(),
          source: pin.source === 'manual' ? 'manual' : 'tofu',
        })
      }
      window.localStorage.removeItem(key)
      changed = true
    } catch {
      // Unreadable legacy data is left alone.
    }
  }
  return changed
}

function readStore(): PinStore {
  if (typeof window === 'undefined') {
    return emptyStore()
  }

  let store = emptyStore()
  try {
    const parsed = JSON.parse(window.localStorage.getItem(STORE_KEY) ?? 'null') as Partial<PinStore> | null
    if (parsed?.v === 2 && Array.isArray(parsed.pins)) {
      store = { v: 2, pins: parsed.pins.filter(isPin) }
    }
  } catch {
    store = emptyStore()
  }

  try {
    if (migrateLegacy(store)) {
      writeStore(store)
    }
  } catch {
    // Storage unavailable: work with what was read.
  }
  return store
}

// Every pin that refers to this agent: same id, or same name (any account).
export function pinsForAgent(agent: Pick<AgentSummary, 'id' | 'name'>): AgentPin[] {
  return readStore().pins.filter((pin) => pin.agent_id === agent.id || pin.name === agent.name)
}

// Pins `fingerprint` for this agent, replacing earlier pins for the same
// agent id or the same name in the same account. Returns false when it could
// not be stored (storage full or blocked).
export function savePin(
  userId: string,
  agent: Pick<AgentSummary, 'id' | 'name' | 'public_key'>,
  fingerprint: string,
  source: PinSource
): boolean {
  if (typeof window === 'undefined') {
    return false
  }
  const store = readStore()
  store.pins = store.pins.filter(
    (pin) => pin.agent_id !== agent.id && !(pin.name === agent.name && (pin.user_id === userId || pin.agent_id === null))
  )
  store.pins.push({
    agent_id: agent.id,
    name: agent.name,
    user_id: userId,
    fingerprint,
    public_key: agent.public_key,
    first_seen: new Date().toISOString(),
    source,
  })
  return writeStore(store)
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
// this browser's pins. Never trusts the server's fingerprint field: it is
// only cross-checked, and a disagreement blocks.
//
// - A pin with the same agent id and another key: mismatch (ids are unique).
// - Otherwise a pin for the same id or name with this key: pinned. Another
//   account on this origin may have its own agent of the same name; its pin
//   doesn't make this one a mismatch as long as one pin matches.
// - Pins for the name exist but none has this key: mismatch.
// - No pin at all: unpinned.
//
// `userId` is accepted for symmetry with savePin; lookups deliberately ignore
// it (see the module comment).
export function checkAgentKey(_userId: string, agent: AgentSummary): AgentKeyCheck {
  let publicKey: Uint8Array
  let fingerprint: string

  try {
    publicKey = decodeAgentPublicKey(agent.public_key)
    fingerprint = agentFingerprint(publicKey)
  } catch {
    return { state: 'invalid', fingerprint: null }
  }

  const pins = pinsForAgent(agent)
  const sameId = pins.filter((pin) => pin.agent_id === agent.id)
  const conflictingId = sameId.find((pin) => pin.fingerprint !== fingerprint)
  if (conflictingId) {
    return { state: 'mismatch', fingerprint, pinnedFingerprint: conflictingId.fingerprint, publicKey }
  }
  if (pins.length > 0 && !pins.some((pin) => pin.fingerprint === fingerprint)) {
    return { state: 'mismatch', fingerprint, pinnedFingerprint: pins[0]!.fingerprint, publicKey }
  }

  if (agent.fingerprint !== fingerprint) {
    return { state: 'invalid', fingerprint }
  }

  return pins.length > 0
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
