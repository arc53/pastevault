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

export const createAgentSchema = z
  .object({
    name: z
      .string()
      .regex(
        /^[a-z0-9][a-z0-9._-]{0,62}$/,
        'name must be 1-63 characters of a-z, 0-9, ".", "_" or "-", starting with a letter or digit'
      ),
    public_key: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/, 'public_key must be a 32-byte X25519 key in unpadded base64url'),
    fingerprint: z
      .string()
      .regex(/^pvk1_[a-z2-7]{32}$/, 'Fingerprint must look like pvk1_ followed by 32 base32 characters'),
  })
  .strict()

export const listAgentsQuerySchema = z.object({
  include_revoked: z.enum(['0', '1', 'true', 'false']).optional(),
})

export const agentParamsSchema = z.object({
  agentId: z.string().min(1).max(128),
})

// Secret requests (spec §2.6).
export const SECRET_REQUEST_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/
export const SECRET_REQUEST_MAX_TTL_SECONDS = 86_400
export const SECRET_REQUEST_DEFAULT_TTL_SECONDS = 600
// Request codes: 8 characters without look-alikes (0/O, 1/I), shown as ABCD-EFGH.
export const SECRET_REQUEST_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

// The reason is shown to a human as untrusted text. Control characters other
// than tab and newline (C0, DEL, C1), bidirectional marks, overrides and
// isolates, and line/paragraph separators could disguise it. Its length is
// counted in Unicode code points (as JSON Schema maxLength and the CLI do).
export const SECRET_REQUEST_REASON_MAX = 500
export const SECRET_REQUEST_REASON_FORBIDDEN =
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/
const reasonSchema = z
  .string()
  .refine((value) => Array.from(value).length <= SECRET_REQUEST_REASON_MAX, 'reason is limited to 500 characters')
  .refine(
    (value) => !SECRET_REQUEST_REASON_FORBIDDEN.test(value),
    'reason must not contain control, bidirectional or line-separator characters'
  )

export const createSecretRequestSchema = z
  .object({
    name: z
      .string()
      .regex(
        SECRET_REQUEST_NAME_PATTERN,
        'name must be 1-128 characters of A-Z, a-z, 0-9, "_", "." or "-", starting with a letter or "_"'
      ),
    reason: reasonSchema.optional(),
    ttl_seconds: z
      .number()
      .int()
      .min(config.SECRET_REQUEST_MIN_TTL_SECONDS)
      .max(SECRET_REQUEST_MAX_TTL_SECONDS)
      .default(SECRET_REQUEST_DEFAULT_TTL_SECONDS),
    accept: z.enum(['text', 'file', 'any']).default('text'),
    public_key: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/, 'public_key must be a 32-byte X25519 key in unpadded base64url'),
    fingerprint: z
      .string()
      .regex(/^pvk1_[a-z2-7]{32}$/, 'Fingerprint must look like pvk1_ followed by 32 base32 characters'),
    agent_id: z.string().min(1).max(128),
  })
  .strict()

export const secretRequestParamsSchema = z.object({
  requestId: z.string().min(1).max(128),
})

// Accepts "ABCD-EFGH", "abcdefgh" and similar; normalised to 8 upper-case
// characters by normalizeRequestCode.
export const secretRequestCodeParamsSchema = z.object({
  code: z.string().min(8).max(16),
})

export const fulfillSecretRequestSchema = z
  .object({
    kind: z.enum(['text', 'file']),
    ciphertext: z.string().min(1).regex(/^[A-Za-z0-9_-]+$/, 'ciphertext must be unpadded base64url'),
    nonce: z.string().regex(/^[A-Za-z0-9_-]{32}$/, 'nonce must be 24 bytes of unpadded base64url'),
    wrapped_key: z
      .string()
      .regex(/^[A-Za-z0-9_-]{140}$/, 'wrapped_key must be a 105-byte base64url PVWRAP1 envelope'),
  })
  .strict()

export const pollSecretRequestSchema = z
  .object({
    poll_token: z.string().min(1).max(128),
  })
  .strict()

export const listSecretRequestsQuerySchema = z.object({
  status: z.enum(['pending', 'fulfilled', 'delivered', 'declined', 'expired', 'cancelled']).optional(),
})
