import { getPrisma } from './db'

interface FileShareRow {
  id: string
  slug: string
  manifest_ciphertext: string | null
  manifest_nonce: string | null
  salt: string | null
  kdf_params: string | null
  created_at: Date | string
  expires_at: Date | string | null
  is_complete: boolean | number
  view_count: number | bigint
  file_count: number | bigint
  total_size_bytes: string
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
}

let schemaEnsured = false

function normalizeDate(value: Date | string | null) {
  if (!value) {
    return null
  }

  return value instanceof Date ? value : new Date(value)
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
    is_complete: typeof row.is_complete === 'boolean' ? row.is_complete : row.is_complete === 1,
    view_count: Number(row.view_count),
    file_count: Number(row.file_count),
    total_size_bytes: row.total_size_bytes,
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
      "total_size_bytes" TEXT NOT NULL DEFAULT '0'
    )
  `)

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
}) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const id = crypto.randomUUID()

  await prisma.$executeRaw`
    INSERT INTO "FileShare" (
      "id",
      "slug",
      "expires_at",
      "salt",
      "kdf_params",
      "file_count",
      "total_size_bytes"
    )
    VALUES (
      ${id},
      ${input.slug},
      ${input.expires_at},
      ${input.salt ?? null},
      ${input.kdf_params ?? null},
      ${input.file_count},
      ${String(input.total_size_bytes)}
    )
  `

  return id
}

export async function getFileShareRecordBySlug(slug: string) {
  await ensureFileShareSchema()
  const prisma = getPrisma()
  const rows = await prisma.$queryRaw<FileShareRow[]>`
    SELECT
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
      "total_size_bytes"
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
      "is_complete" = true
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
    SELECT
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
      "total_size_bytes"
    FROM "FileShare"
    WHERE
      ("expires_at" IS NOT NULL AND "expires_at" <= ${now})
      OR ("is_complete" = false AND "created_at" <= ${incompleteCutoff})
  `

  return rows.map(normalizeRecord)
}

export async function deleteFileSharesByIds(ids: string[]) {
  if (ids.length === 0) {
    return 0
  }

  await ensureFileShareSchema()
  const prisma = getPrisma()
  const placeholders = ids.map(() => '?').join(', ')

  return prisma.$executeRawUnsafe(
    `DELETE FROM "FileShare" WHERE "id" IN (${placeholders})`,
    ...ids
  )
}
