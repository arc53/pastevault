import { Prisma } from '@prisma/client'
import { getPrisma } from './db.js'
import { ensureColumns, timestampType } from './schema-utils.js'

interface FileShareRow {
  id: string
  slug: string
  manifest_ciphertext: string | null
  manifest_nonce: string | null
  salt: string | null
  kdf_params: string | null
  created_at: Date | string
  expires_at: Date | string | null
  is_complete: boolean | number | bigint
  view_count: number | bigint
  file_count: number | bigint
  total_size_bytes: string
  burn_after_read: boolean | number | bigint
  is_burned: boolean | number | bigint
  upload_token_hash: string | null
  download_grant_hash: string | null
  download_grant_expires_at: Date | string | null
  burned_at: Date | string | null
  max_views: number | bigint | null
  recipient_fingerprint: string | null
  recipient_agent_id: string | null
  recipient_user_id: string | null
  wrapped_key: string | null
}

export interface FileShareRecord {
  id: string
  slug: string
  manifest_ciphertext: string | null
  manifest_nonce: string | null
  salt: string | null
  kdf_params: string | null
  created_at: Date
  expires_at: Date | null
  is_complete: boolean
  view_count: number
  file_count: number
  total_size_bytes: string
  burn_after_read: boolean
  is_burned: boolean
  upload_token_hash: string | null
  download_grant_hash: string | null
  download_grant_expires_at: Date | null
  burned_at: Date | null
  max_views: number | null
  recipient_fingerprint: string | null
  recipient_agent_id: string | null
  recipient_user_id: string | null
  wrapped_key: string | null
}

const FILE_SHARE_COLUMNS = Prisma.raw(`
  "id",
  "slug",
  "manifest_ciphertext",
  "manifest_nonce",
  "salt",
  "kdf_params",
  "created_at",
  "expires_at",
  "is_complete",
  "view_count",
  "file_count",
  "total_size_bytes",
  "burn_after_read",
  "is_burned",
  "upload_token_hash",
  "download_grant_hash",
  "download_grant_expires_at",
  "burned_at",
  "max_views",
  "recipient_fingerprint",
  "recipient_agent_id",
  "recipient_user_id",
  "wrapped_key"
`)

// Columns added after the initial release. Fresh tables get them from CREATE
// TABLE; existing databases via an additive ALTER at startup (and the matching
// Postgres migration). Postgres uses TIMESTAMP(3) to match the Prisma schema,
// so the IF NOT EXISTS migration finds an identical column and nothing drifts.
function addedColumns(): Array<[name: string, definition: string]> {
  const timestamp = timestampType()

  return [
    ['burn_after_read', 'BOOLEAN NOT NULL DEFAULT false'],
    ['is_burned', 'BOOLEAN NOT NULL DEFAULT false'],
    ['upload_token_hash', 'TEXT'],
    ['download_grant_hash', 'TEXT'],
    ['download_grant_expires_at', timestamp],
    ['burned_at', timestamp],
    ['max_views', 'INTEGER'],
    ['recipient_fingerprint', 'TEXT'],
    ['recipient_agent_id', 'TEXT'],
    ['recipient_user_id', 'TEXT'],
    ['wrapped_key', 'TEXT'],
  ]
}

let schemaEnsured = false

function normalizeDate(value: Date | string | null) {
  if (!value) {
    return null
  }

  return value instanceof Date ? value : new Date(value)
}

// SQLite returns booleans from raw queries as 0/1.
function normalizeBoolean(value: boolean | number | bigint) {
  return typeof value === 'boolean' ? value : Number(value) === 1
}

function normalizeRecord(row: FileShareRow): FileShareRecord {
  return {
    id: row.id,
    slug: row.slug,
    manifest_ciphertext: row.manifest_ciphertext,
    manifest_nonce: row.manifest_nonce,
    salt: row.salt,
    kdf_params: row.kdf_params,
    created_at: normalizeDate(row.created_at)!,
    expires_at: normalizeDate(row.expires_at),
    is_complete: normalizeBoolean(row.is_complete),
    view_count: Number(row.view_count),
    file_count: Number(row.file_count),
    total_size_bytes: row.total_size_bytes,
    burn_after_read: normalizeBoolean(row.burn_after_read),
    is_burned: normalizeBoolean(row.is_burned),
    upload_token_hash: row.upload_token_hash,
    download_grant_hash: row.download_grant_hash,
    download_grant_expires_at: normalizeDate(row.download_grant_expires_at),
    burned_at: normalizeDate(row.burned_at),
    max_views: row.max_views === null ? null : Number(row.max_views),
    recipient_fingerprint: row.recipient_fingerprint,
    recipient_agent_id: row.recipient_agent_id,
    recipient_user_id: row.recipient_user_id,
    wrapped_key: row.wrapped_key,
  }
}

export async function ensureFileShareSchema() {
  if (schemaEnsured) {
    return
  }

  const prisma = getPrisma()

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "FileShare" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "slug" TEXT NOT NULL UNIQUE,
      "manifest_ciphertext" TEXT,
      "manifest_nonce" TEXT,
      "salt" TEXT,
      "kdf_params" TEXT,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "is_complete" BOOLEAN NOT NULL DEFAULT false,
      "view_count" INTEGER NOT NULL DEFAULT 0,
      "file_count" INTEGER NOT NULL DEFAULT 0,
      "total_size_bytes" TEXT NOT NULL DEFAULT '0',
      ${addedColumns()
        .map(([name, definition]) => `"${name}" ${definition}`)
        .join(',\n      ')}
    )
  `)

  await ensureColumns('FileShare', addedColumns())

  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "FileShare_expires_at_idx" ON "FileShare"("expires_at")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "FileShare_slug_idx" ON "FileShare"("slug")'
  )

  schemaEnsured = true
}

export async function createFileShareRecord(input: {
  slug: string
  expires_at: Date | null
  salt?: string
  kdf_params?: string
  file_count: number
  total_size_bytes: number
  burn_after_read: boolean
  max_views: number | null
  recipient: {
    fingerprint: string
    agent_id: string | null
    user_id: string | null
    wrapped_key: string
  } | null
  upload_token_hash: string
}) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const id = crypto.randomUUID()
  const burnAfterRead = input.burn_after_read ? Prisma.sql`true` : Prisma.sql`false`

  await prisma.$executeRaw`
    INSERT INTO "FileShare" (
      "id",
      "slug",
      "expires_at",
      "salt",
      "kdf_params",
      "file_count",
      "total_size_bytes",
      "burn_after_read",
      "max_views",
      "recipient_fingerprint",
      "recipient_agent_id",
      "recipient_user_id",
      "wrapped_key",
      "upload_token_hash"
    )
    VALUES (
      ${id},
      ${input.slug},
      ${input.expires_at},
      ${input.salt ?? null},
      ${input.kdf_params ?? null},
      ${input.file_count},
      ${String(input.total_size_bytes)},
      ${burnAfterRead},
      ${input.max_views},
      ${input.recipient?.fingerprint ?? null},
      ${input.recipient?.agent_id ?? null},
      ${input.recipient?.user_id ?? null},
      ${input.recipient?.wrapped_key ?? null},
      ${input.upload_token_hash}
    )
  `

  return id
}

export async function getFileShareRecordBySlug(slug: string) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const rows = await prisma.$queryRaw<FileShareRow[]>`
    SELECT ${FILE_SHARE_COLUMNS}
    FROM "FileShare"
    WHERE "slug" = ${slug}
    LIMIT 1
  `

  const row = rows[0]
  return row ? normalizeRecord(row) : null
}

export async function incrementFileShareViewCount(id: string) {
  await ensureFileShareSchema()
  const prisma = getPrisma()

  await prisma.$executeRaw`
    UPDATE "FileShare"
    SET "view_count" = "view_count" + 1
    WHERE "id" = ${id}
  `
}

// Atomically consumes one view of a view-limited share. The view that reaches
// the limit burns the share: it wipes the manifest and key material and stores
// the download grant in the same statement. Returns null when the share was
// already used up (or burned) by other readers.
export async function consumeFileShareView(
  id: string,
  maxViews: number,
  downloadGrantHash: string,
  downloadGrantExpiresAt: Date,
  burnedAt: Date
) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const final = Prisma.sql`"view_count" + 1 >= ${maxViews}`

  const rows = await prisma.$queryRaw<
    Array<{ view_count: number | bigint; is_burned: boolean | number | bigint }>
  >`
    UPDATE "FileShare"
    SET
      "view_count" = "view_count" + 1,
      "is_burned" = CASE WHEN ${final} THEN true ELSE false END,
      "manifest_ciphertext" = CASE WHEN ${final} THEN NULL ELSE "manifest_ciphertext" END,
      "manifest_nonce" = CASE WHEN ${final} THEN NULL ELSE "manifest_nonce" END,
      "salt" = CASE WHEN ${final} THEN NULL ELSE "salt" END,
      "kdf_params" = CASE WHEN ${final} THEN NULL ELSE "kdf_params" END,
      "wrapped_key" = CASE WHEN ${final} THEN NULL ELSE "wrapped_key" END,
      "download_grant_hash" = CASE WHEN ${final} THEN ${downloadGrantHash} ELSE "download_grant_hash" END,
      "download_grant_expires_at" = CASE WHEN ${final} THEN ${downloadGrantExpiresAt} ELSE "download_grant_expires_at" END,
      "burned_at" = CASE WHEN ${final} THEN ${burnedAt} ELSE "burned_at" END
    WHERE "id" = ${id}
      AND "is_complete" = true
      AND "is_burned" = false
      AND "view_count" < ${maxViews}
    RETURNING "view_count", "is_burned"
  `

  const row = rows[0]
  return row
    ? { view_count: Number(row.view_count), is_burned: normalizeBoolean(row.is_burned) }
    : null
}

// Slides a burned share's download grant forward. Never shortens it, so
// concurrent chunk requests can't race the expiry backwards.
export async function extendFileShareDownloadGrant(id: string, expiresAt: Date) {
  await ensureFileShareSchema()
  const prisma = getPrisma()

  await prisma.$executeRaw`
    UPDATE "FileShare"
    SET "download_grant_expires_at" = ${expiresAt}
    WHERE "id" = ${id}
      AND "is_burned" = true
      AND "download_grant_expires_at" < ${expiresAt}
  `
}

export async function completeFileShareRecord(
  slug: string,
  manifestCiphertext: string,
  manifestNonce: string
) {
  await ensureFileShareSchema()
  const prisma = getPrisma()

  const updatedRows = await prisma.$executeRaw`
    UPDATE "FileShare"
    SET
      "manifest_ciphertext" = ${manifestCiphertext},
      "manifest_nonce" = ${manifestNonce},
      "is_complete" = true,
      "upload_token_hash" = NULL
    WHERE "slug" = ${slug}
      AND "is_complete" = false
  `

  return updatedRows > 0
}

export async function listExpiredOrAbandonedFileShares(
  now: Date,
  incompleteCutoff: Date
) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const rows = await prisma.$queryRaw<FileShareRow[]>`
    SELECT ${FILE_SHARE_COLUMNS}
    FROM "FileShare"
    WHERE
      ("expires_at" IS NOT NULL AND "expires_at" <= ${now})
      OR ("is_complete" = false AND "created_at" <= ${incompleteCutoff})
      OR (
        "is_burned" = true
        AND ("download_grant_expires_at" IS NULL OR "download_grant_expires_at" <= ${now})
      )
  `

  return rows.map(normalizeRecord)
}

export async function deleteFileSharesByIds(ids: string[]) {
  if (ids.length === 0) {
    return 0
  }

  await ensureFileShareSchema()
  const prisma = getPrisma()

  return prisma.$executeRaw`
    DELETE FROM "FileShare" WHERE "id" IN (${Prisma.join(ids)})
  `
}
