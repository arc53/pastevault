import { Prisma } from '@prisma/client'
import { getPrisma, resolveDatabaseProvider } from './db.js'

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
  "burned_at"
`)

// Columns added after the initial release. Fresh tables get them from CREATE
// TABLE; existing databases via an additive ALTER at startup (and the matching
// Postgres migration). Postgres uses TIMESTAMP(3) to match the Prisma schema,
// so the IF NOT EXISTS migration finds an identical column and nothing drifts.
function addedColumns(): Array<[name: string, definition: string]> {
  const timestamp =
    resolveDatabaseProvider() === 'postgresql' ? 'TIMESTAMP(3)' : 'TIMESTAMP'

  return [
    ['burn_after_read', 'BOOLEAN NOT NULL DEFAULT false'],
    ['is_burned', 'BOOLEAN NOT NULL DEFAULT false'],
    ['upload_token_hash', 'TEXT'],
    ['download_grant_hash', 'TEXT'],
    ['download_grant_expires_at', timestamp],
    ['burned_at', timestamp],
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
  }
}

async function listFileShareColumns() {
  const prisma = getPrisma()

  if (resolveDatabaseProvider() === 'postgresql') {
    const rows = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT "column_name"
      FROM information_schema.columns
      WHERE "table_schema" = current_schema() AND "table_name" = 'FileShare'
    `
    return new Set(rows.map((row) => row.column_name))
  }

  const rows = await prisma.$queryRawUnsafe<Array<{ name: string }>>(
    'PRAGMA table_info("FileShare")'
  )
  return new Set(rows.map((row) => row.name))
}

// Only ALTER when a column is actually missing, so routine boots don't take
// an ACCESS EXCLUSIVE lock on Postgres.
async function ensureAddedColumns() {
  const prisma = getPrisma()
  const existing = await listFileShareColumns()
  const isPostgres = resolveDatabaseProvider() === 'postgresql'

  for (const [name, definition] of addedColumns()) {
    if (existing.has(name)) {
      continue
    }

    try {
      await prisma.$executeRawUnsafe(
        `ALTER TABLE "FileShare" ADD COLUMN ${isPostgres ? 'IF NOT EXISTS ' : ''}"${name}" ${definition}`
      )
    } catch (error: unknown) {
      // Another instance booting at the same time may have added it first.
      if (!(error instanceof Error && /duplicate column/i.test(error.message))) {
        throw error
      }
    }
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

  await ensureAddedColumns()

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

// Atomically consumes a burn-after-read share: only one caller can flip
// is_burned, and the manifest is wiped in the same statement. Returns false
// when another reader already burned it.
export async function burnFileShareRecord(
  id: string,
  downloadGrantHash: string,
  downloadGrantExpiresAt: Date,
  burnedAt: Date
) {
  await ensureFileShareSchema()
  const prisma = getPrisma()

  const updatedRows = await prisma.$executeRaw`
    UPDATE "FileShare"
    SET
      "is_burned" = true,
      "view_count" = "view_count" + 1,
      "manifest_ciphertext" = NULL,
      "manifest_nonce" = NULL,
      "salt" = NULL,
      "kdf_params" = NULL,
      "download_grant_hash" = ${downloadGrantHash},
      "download_grant_expires_at" = ${downloadGrantExpiresAt},
      "burned_at" = ${burnedAt}
    WHERE "id" = ${id}
      AND "is_complete" = true
      AND "is_burned" = false
  `

  return updatedRows > 0
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
