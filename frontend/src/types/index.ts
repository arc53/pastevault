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
}

export interface GetPasteResponse {
  metadata: PasteMetadata
  ciphertext: string
  nonce: string
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
}

export interface CreateFileShareRequest {
  slug?: string
  salt?: string
  kdf_params?: string
  expires_in_hours?: number
  file_count: number
  total_size_bytes: number
}

export interface CreateFileShareResponse {
  slug: string
  expires_at: string | null
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
}

export interface FileShareCapabilities {
  enabled: boolean
  max_share_size_bytes: number
  max_files: number
  chunk_size_bytes: number
}

export interface CapabilitiesResponse {
  file_shares: FileShareCapabilities
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
}

export interface ListAccountSharesResponse {
  shares: AccountShare[]
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
