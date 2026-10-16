export interface PasteMetadata {
  id: string
  slug: string
  created_at: Date
  expires_at: Date | null
  burn_after_read: boolean
  is_burned: boolean
  view_count: number
  max_views: number | null
  views_remaining: number | null
  salt?: string
  kdf_params?: string
}

// A share sealed to one recipient key (PVWRAP1). agent_id names an agent of
// the sender's account; without it the share is sealed to a raw public key.
export interface ShareRecipientInput {
  agent_id?: string
  fingerprint: string
  wrapped_key: string
}

// Options shared by pastes and file shares. expires_in_hours and
// expires_in_minutes are mutually exclusive; burn_after_read is max_views 1.
export interface ShareOptionsRequest {
  salt?: string
  kdf_params?: string
  expires_in_hours?: number
  expires_in_minutes?: number
  burn_after_read?: boolean
  max_views?: number
  recipient?: ShareRecipientInput
}

export interface CreatePasteRequest extends ShareOptionsRequest {
  ciphertext: string
  nonce: string
  slug?: string
}

export interface CreatePasteResponse {
  slug: string
  expires_at: Date | null
  max_views: number | null
}

export interface GetPasteResponse {
  metadata: PasteMetadata
  ciphertext: string
  nonce: string
  salt?: string
  kdf_params?: string
  // Sealed shares only.
  wrapped_key?: string
  recipient_fingerprint?: string
}

export interface ShareRecipientMeta {
  fingerprint: string
}

// Non-consuming view of a paste: safe for previews and for deciding whether to reveal.
export interface PasteMetaResponse {
  slug: string
  created_at: Date
  expires_at: Date | null
  burn_after_read: boolean
  is_burned: boolean
  password_protected: boolean
  salt?: string
  kdf_params?: string
  max_views: number | null
  views_remaining: number | null
  recipient: ShareRecipientMeta | null
  requires_recipient_auth: boolean
}

export interface FileShareMetadata {
  id: string
  slug: string
  created_at: Date
  expires_at: Date | null
  view_count: number
  file_count: number
  total_size_bytes: string
  burn_after_read: boolean
  is_burned: boolean
  max_views: number | null
  views_remaining: number | null
}

export interface CreateFileShareRequest extends ShareOptionsRequest {
  slug?: string
  file_count: number
  total_size_bytes: number
}

export interface CreateFileShareResponse {
  slug: string
  expires_at: Date | null
  burn_after_read: boolean
  max_views: number | null
  // Required as X-Upload-Token for chunk uploads and completion; shown only once.
  upload_token: string
}

export interface CompleteFileShareRequest {
  manifest_ciphertext: string
  manifest_nonce: string
}

export interface GetFileShareResponse {
  metadata: FileShareMetadata
  manifest_ciphertext: string
  manifest_nonce: string
  salt?: string
  kdf_params?: string
  // Final view of a view-limited share only: send as X-Download-Grant to fetch chunks.
  download_grant?: string
  download_grant_expires_at?: Date
  // Sealed shares only.
  wrapped_key?: string
  recipient_fingerprint?: string
}

export interface FileShareMetaResponse {
  slug: string
  created_at: Date
  expires_at: Date | null
  burn_after_read: boolean
  is_burned: boolean
  password_protected: boolean
  salt?: string
  kdf_params?: string
  file_count: number
  total_size_bytes: string
  max_views: number | null
  views_remaining: number | null
  recipient: ShareRecipientMeta | null
  requires_recipient_auth: boolean
}

export interface CapabilitiesResponse {
  // 2: tokens, expires_in_minutes, max_views, audit (see features).
  api_version: number
  auth: {
    enabled: boolean
    signup_enabled: boolean
  }
  file_shares: {
    enabled: boolean
    max_share_size_bytes: number
    max_files: number
    chunk_size_bytes: number
    burn_after_read: boolean
  }
  // agents needs accounts; sealed_shares (to a raw public key) works without.
  features: {
    expires_in_minutes: boolean
    max_views: boolean
    api_tokens: boolean
    agents: boolean
    sealed_shares: boolean
    secret_requests: boolean
    audit: boolean
  }
  limits: {
    max_views: number
    max_secret_request_bytes: number
    min_secret_request_ttl_seconds: number
  }
}

export type OwnedShareType = 'paste' | 'file_share'

export type OwnedShareStatus =
  | 'uploading'
  | 'active'
  | 'burned'
  | 'expired'
  | 'deleted'
  | 'abandoned'

export interface AccountShare {
  id: string
  share_type: OwnedShareType
  slug: string
  status: OwnedShareStatus
  created_at: Date
  expires_at: Date | null
  deleted_at: Date | null
  first_viewed_at: Date | null
  last_viewed_at: Date | null
  view_count: number
  burn_after_read: boolean
  file_count: number | null
  total_size_bytes: string | null
  is_password_protected: boolean
  can_delete: boolean
  max_views: number | null
  recipient_fingerprint: string | null
  recipient_agent_name: string | null
}

export interface ListAccountSharesResponse {
  shares: AccountShare[]
  // Set when `limit` was given and more shares follow.
  next_cursor: string | null
}

export type ApiScope =
  | 'shares:create'
  | 'shares:read'
  | 'shares:revoke'
  | 'shares:receive'
  | 'agents:read'
  | 'agents:write'
  | 'requests:create'
  | 'audit:read'

export interface MeResponse {
  user: {
    id: string
    username: string | null
    name: string
  }
  auth: {
    kind: 'session' | 'token'
    token_id?: string
    scopes: ApiScope[]
    agent?: {
      id: string
      name: string
      fingerprint: string
    }
  }
}

export interface CreateApiTokenRequest {
  name: string
  scopes?: ApiScope[]
  // 1..365, default 90; null for a token that never expires.
  expires_in_days?: number | null
  agent_id?: string
}

// The token itself is only ever returned here, once.
export interface CreateApiTokenResponse {
  id: string
  token: string
  name: string
  prefix: string
  scopes: ApiScope[]
  agent_id: string | null
  expires_at: Date | null
}

export interface ApiTokenSummary {
  id: string
  name: string
  prefix: string
  scopes: ApiScope[]
  agent: { id: string; name: string } | null
  created_at: Date
  expires_at: Date | null
  last_used_at: Date | null
  revoked_at: Date | null
}

export interface ListApiTokensResponse {
  tokens: ApiTokenSummary[]
}

export interface AuditEventResponse {
  id: string
  subject_type: string
  subject_id: string | null
  slug: string | null
  event: string
  actor_kind: string
  actor_agent: { id: string; name: string | null } | null
  actor_token_id: string | null
  client: string | null
  ip_prefix: string | null
  created_at: Date
  details: Record<string, unknown> | null
}

export interface ListAuditEventsResponse {
  events: AuditEventResponse[]
  next_cursor: string | null
}

export interface ListShareEventsResponse {
  events: AuditEventResponse[]
}

export interface AgentSummary {
  id: string
  name: string
  kind: string
  // X25519 public key, unpadded base64url. Clients recompute the fingerprint
  // from it instead of trusting `fingerprint`.
  public_key: string
  fingerprint: string
  created_at: Date
  last_used_at: Date | null
  revoked_at: Date | null
}

export interface CreateAgentRequest {
  name: string
  public_key: string
  fingerprint: string
}

export interface CreateAgentResponse {
  agent: AgentSummary
  // True when the calling API token was unbound and is now bound to this agent.
  token_bound: boolean
}

export interface ListAgentsResponse {
  agents: AgentSummary[]
}

export interface RevokeAgentResponse {
  agent: AgentSummary
  tokens_revoked: number
}
