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