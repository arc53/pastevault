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
