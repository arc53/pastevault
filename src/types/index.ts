export interface PasteMetadata {
  id: string
  slug: string
  created_at: Date
  expires_at: Date | null
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
  expires_at: Date | null
}

export interface GetPasteResponse {
  metadata: PasteMetadata
  ciphertext: string
  nonce: string
  salt?: string
  kdf_params?: string
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
  expires_at: Date | null
  burn_after_read: boolean
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
  // Burn-after-read shares only: send as X-Download-Grant to fetch chunks.
  download_grant?: string
  download_grant_expires_at?: Date
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
}

export interface CapabilitiesResponse {
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
}

export interface ListAccountSharesResponse {
  shares: AccountShare[]
}
