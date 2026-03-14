import { z } from 'zod'
import { config } from './config'

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

const fileIdSchema = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/)

export const createFileShareSchema = z.object({
  slug: z.string().min(1).optional(),
  salt: z.string().optional(),
  kdf_params: z.string().optional(),
  expires_in_hours: z.number().min(1).max(8760).optional(),
  file_count: z.number().int().min(1).max(config.MAX_FILE_SHARE_FILES),
  total_size_bytes: z.number().int().positive().max(config.MAX_FILE_SHARE_SIZE_BYTES),
})

export const completeFileShareSchema = z.object({
  manifest_ciphertext: z.string().min(1),
  manifest_nonce: z.string().length(32),
})

export const getFileShareParamsSchema = z.object({
  slug: z.string().min(1),
})

export const fileShareChunkParamsSchema = z.object({
  slug: z.string().min(1),
  fileId: fileIdSchema,
  chunkIndex: z.coerce.number().int().min(0).max(1_000_000),
})
