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