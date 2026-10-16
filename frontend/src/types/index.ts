export interface PasteContent {
  title: string
  body: string
  render_mode: 'markdown' | 'plain'
  language_hint?: string
}

export interface PasteMetadata {
  id: string
  slug: string
  created_at: string
  expires_at: string | null
  burn_after_read: boolean
  is_burned: boolean
  view_count: number
  // Present on servers with capabilities.features.max_views.
  max_views?: number | null
  views_remaining?: number | null
  salt?: string
  kdf_params?: string
}

export interface CreatePasteRequest {
  ciphertext: string
  nonce: string
  slug?: string
  salt?: string
  kdf_params?: string
  expires_in_hours?: number
  burn_after_read?: boolean
  max_views?: number
  recipient?: ShareRecipientRequest
}

// The content key sealed to an agent (PVWRAP1); see sealToRecipient in
// lib/wrap.ts. A sealed share carries no salt.
export interface ShareRecipientRequest {
  agent_id?: string
  fingerprint: string
  wrapped_key: string
}

export interface CreatePasteResponse {
  slug: string
  expires_at: string | null
  max_views?: number | null
}

export interface GetPasteResponse {
  metadata: PasteMetadata
  ciphertext: string
  nonce: string
  salt?: string
  kdf_params?: string
  // Shares sealed to a recipient key only.
  wrapped_key?: string
  recipient_fingerprint?: string
}

export interface ShareRecipientMeta {
  fingerprint: string
}

// Fields added with api_version 2; absent on older servers.
export interface ShareLimitsMeta {
  max_views?: number | null
  views_remaining?: number | null
  recipient?: ShareRecipientMeta | null
  requires_recipient_auth?: boolean
}

export interface PasteMetaResponse extends ShareLimitsMeta {
  slug: string
  created_at: string
  expires_at: string | null
  burn_after_read: boolean
  is_burned: boolean
  password_protected: boolean
  salt?: string
  kdf_params?: string
}

export interface FileShareMetadata {
  id: string
  slug: string
  created_at: string
  expires_at: string | null
  view_count: number
  file_count: number
  total_size_bytes: string
  burn_after_read: boolean
  is_burned: boolean
  max_views?: number | null
  views_remaining?: number | null
}

export interface CreateFileShareRequest {
  slug?: string
  salt?: string
  kdf_params?: string
  expires_in_hours?: number
  file_count: number
  total_size_bytes: number
  burn_after_read?: boolean
  max_views?: number
  recipient?: ShareRecipientRequest
}

export interface CreateFileShareResponse {
  slug: string
  expires_at: string | null
  burn_after_read: boolean
  max_views?: number | null
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
  download_grant?: string
  download_grant_expires_at?: string
  wrapped_key?: string
  recipient_fingerprint?: string
}

export interface FileShareMetaResponse extends ShareLimitsMeta {
  slug: string
  created_at: string
  expires_at: string | null
  burn_after_read: boolean
  is_burned: boolean
  password_protected: boolean
  salt?: string
  kdf_params?: string
  file_count: number
  total_size_bytes: string
}

export interface FileShareCapabilities {
  enabled: boolean
  max_share_size_bytes: number
  max_files: number
  chunk_size_bytes: number
  burn_after_read: boolean
}

export interface CapabilitiesFeatures {
  expires_in_minutes: boolean
  max_views: boolean
  api_tokens: boolean
  agents: boolean
  sealed_shares: boolean
  secret_requests: boolean
  audit: boolean
}

export interface CapabilitiesResponse {
  auth: {
    enabled: boolean
    signup_enabled: boolean
  }
  file_shares: FileShareCapabilities
  // api_version 2 and later.
  api_version?: number
  features?: CapabilitiesFeatures
  limits?: {
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
  created_at: string
  expires_at: string | null
  deleted_at: string | null
  first_viewed_at: string | null
  last_viewed_at: string | null
  view_count: number
  burn_after_read: boolean
  file_count: number | null
  total_size_bytes: string | null
  is_password_protected: boolean
  can_delete: boolean
  max_views?: number | null
  recipient_fingerprint?: string | null
  recipient_agent_name?: string | null
}

export interface ListAccountSharesResponse {
  shares: AccountShare[]
  next_cursor?: string | null
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

export interface AgentSummary {
  id: string
  name: string
  kind: string
  // X25519 public key, unpadded base64url. Always recompute the fingerprint
  // from it; never trust `fingerprint`.
  public_key: string
  fingerprint: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}

export interface ListAgentsResponse {
  agents: AgentSummary[]
}

export interface RevokeAgentResponse {
  agent: AgentSummary
  tokens_revoked: number
}

export interface ApiTokenSummary {
  id: string
  name: string
  prefix: string
  scopes: ApiScope[]
  agent: { id: string; name: string } | null
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

export interface ListApiTokensResponse {
  tokens: ApiTokenSummary[]
}

export interface CreateApiTokenRequest {
  name: string
  scopes?: ApiScope[]
  // 1..365; null for a token that never expires.
  expires_in_days?: number | null
  agent_id?: string
}

// The only response that ever carries the token itself.
export interface CreateApiTokenResponse {
  id: string
  token: string
  name: string
  prefix: string
  scopes: ApiScope[]
  agent_id: string | null
  expires_at: string | null
}

export type AuditActorKind = 'owner' | 'recipient' | 'anonymous' | 'system'

export interface AuditEvent {
  id: string
  subject_type: string
  subject_id: string | null
  slug: string | null
  event: string
  actor_kind: AuditActorKind | string
  actor_agent: { id: string; name: string | null } | null
  actor_token_id: string | null
  client: string | null
  ip_prefix: string | null
  created_at: string
  details: Record<string, unknown> | null
}

export interface ListAuditEventsResponse {
  events: AuditEvent[]
  next_cursor: string | null
}

export interface ListShareEventsResponse {
  events: AuditEvent[]
}

export interface EncryptionResult {
  ciphertext: string
  nonce: string
  key: Uint8Array
}

export interface PasswordEncryptionResult {
  ciphertext: string
  nonce: string
  salt: string
  kdf_params: string
}

export interface Draft {
  title: string
  body: string
  language_hint?: string
  expires_in_hours?: number
  burn_after_read: boolean
  password_protected: boolean
  saved_at: number
  // Identifies a single write, so a tab only clears drafts it saved or restored itself.
  id: string
}

export interface FileShareChunk {
  index: number
  nonce: string
  plaintext_size: number
}

export interface FileShareManifestFile {
  id: string
  name: string
  size: number
  type: string
  last_modified: number
  chunks: FileShareChunk[]
}

export interface FileShareManifest {
  version: 'v1'
  paste?: PasteContent
  files: FileShareManifestFile[]
}
