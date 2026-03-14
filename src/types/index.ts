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

export interface FileShareMetadata {
  id: string
  slug: string
  created_at: Date
  expires_at: Date | null
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
  expires_at: Date | null
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

export interface CapabilitiesResponse {
  file_shares: {
    enabled: boolean
    max_share_size_bytes: number
    max_files: number
    chunk_size_bytes: number
  }
}
