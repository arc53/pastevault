import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify'
import { z, ZodError } from 'zod'
import { config } from './config.js'

// Route plugins install this so schema violations become 400s instead of 500s.
export function validationErrorHandler(
  error: FastifyError | ZodError,
  _request: FastifyRequest,
  reply: FastifyReply
) {
  if (error instanceof ZodError) {
    const issue = error.issues[0]
    const field = issue?.path.length ? `${issue.path.join('.')}: ` : ''
    return reply.code(400).send({
      error: `Invalid request: ${field}${issue?.message ?? 'validation failed'}`,
    })
  }

  throw error
}

// Client-chosen slugs end up in URLs, storage keys and AAD, so keep them URL-safe.
// Covers nanoid(12) from the web app and 12-char base64url slugs from the Go CLI.
export const slugSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{6,64}$/, 'Slug must be 6-64 characters of A-Z, a-z, 0-9, "_" or "-"')

export const createPasteSchema = z.object({
  ciphertext: z.string().min(1),
  nonce: z.string().length(32), // 24 bytes base64url = 32 chars
  slug: slugSchema.optional(), // Client can provide slug for AAD consistency
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
  slug: slugSchema.optional(),
  salt: z.string().optional(),
  kdf_params: z.string().optional(),
  expires_in_hours: z.number().min(1).max(8760).optional(),
  file_count: z.number().int().min(1).max(config.MAX_FILE_SHARE_FILES),
  total_size_bytes: z.number().int().positive().max(config.MAX_FILE_SHARE_SIZE_BYTES),
  burn_after_read: z.boolean().default(false),
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

export const ownedShareTypeSchema = z.enum(['paste', 'file_share'])
export const ownedShareStatusSchema = z.enum([
  'uploading',
  'active',
  'burned',
  'expired',
  'deleted',
  'abandoned',
])

export const accountSharesQuerySchema = z.object({
  share_type: ownedShareTypeSchema.optional(),
  status: ownedShareStatusSchema.optional(),
})

export const accountShareParamsSchema = z.object({
  shareId: z.string().min(1),
})
