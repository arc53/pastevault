import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify'
import { z, ZodError } from 'zod'
import { SCOPES } from './api-tokens.js'
import { config } from './config.js'

// Thrown by handlers and helpers (auth, scope checks) to end a request with a
// specific status and JSON body.
export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: Record<string, unknown>
  ) {
    super(typeof body.error === 'string' ? body.error : `HTTP ${statusCode}`)
    this.name = 'HttpError'
  }
}

// Route plugins install this so schema violations become 400s instead of 500s.
export function validationErrorHandler(
  error: FastifyError | ZodError | HttpError,
  _request: FastifyRequest,
  reply: FastifyReply
) {
  if (error instanceof HttpError) {
    return reply.code(error.statusCode).send(error.body)
  }

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

export const MAX_VIEWS_LIMIT = 1000

// A share sealed to one recipient key: the content key wrapped with PVWRAP1
// (105 bytes, so 140 base64url characters) and the recipient's fingerprint.
const recipientSchema = z
  .object({
    agent_id: z.string().min(1).max(128).optional(),
    fingerprint: z
      .string()
      .regex(/^pvk1_[a-z2-7]{32}$/, 'Fingerprint must look like pvk1_ followed by 32 base32 characters'),
    wrapped_key: z
      .string()
      .regex(/^[A-Za-z0-9_-]{140}$/, 'wrapped_key must be a 105-byte base64url PVWRAP1 envelope'),
  })
  .strict()

// Expiry and view limits shared by pastes and file shares.
const shareOptionsShape = {
  salt: z.string().optional(),
  kdf_params: z.string().optional(),
  expires_in_hours: z.number().min(1).max(8760).optional(), // Max 1 year
  expires_in_minutes: z.number().int().min(1).max(525600).optional(), // Max 1 year
  burn_after_read: z.boolean().default(false),
  max_views: z.number().int().min(1).max(MAX_VIEWS_LIMIT).optional(),
  recipient: recipientSchema.optional(),
}

function checkShareOptions(
  body: {
    salt?: string
    expires_in_hours?: number
    expires_in_minutes?: number
    burn_after_read: boolean
    max_views?: number
    recipient?: unknown
  },
  context: z.RefinementCtx
) {
  if (body.expires_in_hours !== undefined && body.expires_in_minutes !== undefined) {
    context.addIssue({
      code: 'custom',
      message: 'expires_in_hours and expires_in_minutes are mutually exclusive',
    })
  }

  if (body.burn_after_read && body.max_views !== undefined && body.max_views !== 1) {
    context.addIssue({
      code: 'custom',
      path: ['max_views'],
      message: 'burn_after_read means max_views 1',
    })
  }

  if (body.recipient && body.salt !== undefined) {
    context.addIssue({
      code: 'custom',
      path: ['recipient'],
      message: 'A share sealed to a recipient cannot also be password protected',
    })
  }
}

// Stage 1 stores shares sealed to a raw public key. Sealing to an agent of the
// account needs agent lookup and recipient auth on read, which come with the
// agents API; until then such requests are refused instead of half-honoured.
export function rejectUnsupportedRecipient(recipient: { agent_id?: string } | undefined) {
  if (recipient?.agent_id !== undefined) {
    throw new HttpError(400, {
      error: 'recipient.agent_id is not supported by this server yet',
      code: 'recipient_agent_unsupported',
    })
  }
}

export const createPasteSchema = z
  .object({
    ciphertext: z.string().min(1),
    nonce: z.string().length(32), // 24 bytes base64url = 32 chars
    slug: slugSchema.optional(), // Client can provide slug for AAD consistency
    ...shareOptionsShape,
  })
  .superRefine(checkShareOptions)

export const getPasteParamsSchema = z.object({
  slug: z.string().min(1),
})

const fileIdSchema = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/)

export const createFileShareSchema = z
  .object({
    slug: slugSchema.optional(),
    file_count: z.number().int().min(1).max(config.MAX_FILE_SHARE_FILES),
    total_size_bytes: z.number().int().positive().max(config.MAX_FILE_SHARE_SIZE_BYTES),
    ...shareOptionsShape,
  })
  .superRefine(checkShareOptions)

export type ShareOptionsInput = z.infer<typeof createPasteSchema>

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

const cursorQuerySchema = z.string().max(512).optional()

export const accountSharesQuerySchema = z.object({
  share_type: ownedShareTypeSchema.optional(),
  status: ownedShareStatusSchema.optional(),
  slug: z.string().min(1).max(64).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  cursor: cursorQuerySchema,
})

export const accountShareParamsSchema = z.object({
  shareId: z.string().min(1),
})

// "24h", "15m", "7d" back from now, or an ISO-8601 timestamp.
const sinceSchema = z
  .string()
  .max(64)
  .transform((value, context) => {
    const relative = /^(\d{1,6})([mhd])$/.exec(value)
    if (relative) {
      const unitMs = { m: 60_000, h: 3_600_000, d: 86_400_000 }[relative[2] as 'm' | 'h' | 'd']
      return new Date(Date.now() - Number(relative[1]) * unitMs)
    }

    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      context.addIssue({ code: 'custom', message: 'since must be a duration like 24h or a timestamp' })
      return z.NEVER
    }
    return date
  })

export const auditQuerySchema = z.object({
  since: sinceSchema.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: cursorQuerySchema,
  event: z
    .string()
    .regex(/^[a-z_]+\.[a-z_]+$/, 'event must look like share.viewed')
    .optional(),
})

export const createApiTokenSchema = z
  .object({
    name: z.string().trim().min(1).max(64),
    scopes: z.array(z.enum(SCOPES)).min(1).max(SCOPES.length).optional(),
    // Days until expiry; null means the token never expires.
    expires_in_days: z.number().int().min(1).max(365).nullable().default(90),
    agent_id: z.string().min(1).max(128).optional(),
  })
  .strict()

export const apiTokenParamsSchema = z.object({
  tokenId: z.string().min(1).max(128),
})
