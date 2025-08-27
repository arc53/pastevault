import { z } from 'zod'

export const createPasteSchema = z.object({
  ciphertext: z.string().min(1),
  nonce: z.string().length(32), // 24 bytes base64url = 32 chars
  slug: z.string().optional(), // Client can provide slug for AAD consistency
  salt: z.string().optional(),
  kdf_params: z.string().optional(),
  expires_in_hours: z.number().min(1).max(8760).optional(), // Max 1 year
  burn_after_read: z.boolean().default(false),
})

export const getPasteParamsSchema = z.object({
  slug: z.string().min(1),
})