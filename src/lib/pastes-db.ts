import { Prisma } from '@prisma/client'
import { getPrisma } from './db.js'
import { ensureColumns } from './schema-utils.js'

let schemaEnsured = false

// Columns added after the initial release; see file-shares-db.ts.
function addedColumns(): Array<[name: string, definition: string]> {
  return [
    ['max_views', 'INTEGER'],
    ['recipient_fingerprint', 'TEXT'],
    ['recipient_agent_id', 'TEXT'],
    ['recipient_user_id', 'TEXT'],
    ['wrapped_key', 'TEXT'],
  ]
}

// Must run before any Prisma model query on Paste: the model API selects every
// column in the schema and fails on databases that predate one.
export async function ensurePasteSchema() {
  if (schemaEnsured) {
    return
  }

  const prisma = getPrisma()

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "Paste" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "slug" TEXT NOT NULL UNIQUE,
      "ciphertext" TEXT NOT NULL,
      "nonce" TEXT NOT NULL,
      "salt" TEXT,
      "kdf_params" TEXT,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
      "is_burned" BOOLEAN NOT NULL DEFAULT false,
      "view_count" INTEGER NOT NULL DEFAULT 0,
      ${addedColumns()
        .map(([name, definition]) => `"${name}" ${definition}`)
        .join(',\n      ')}
    )
  `)

  await ensureColumns('Paste', addedColumns())

  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "Paste_expires_at_idx" ON "Paste"("expires_at")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "Paste_slug_idx" ON "Paste"("slug")'
  )

  schemaEnsured = true
}

// Atomically consumes one view of a view-limited paste. The view that reaches
// the limit burns the paste and wipes its content and key material in the same
// statement, so exactly one reader can take the last view. Returns null when
// other readers already used up the views.
export async function consumePasteView(id: string, maxViews: number) {
  await ensurePasteSchema()
  const final = Prisma.sql`"view_count" + 1 >= ${maxViews}`

  const rows = await getPrisma().$queryRaw<
    Array<{ view_count: number | bigint; is_burned: boolean | number | bigint }>
  >`
    UPDATE "Paste"
    SET
      "view_count" = "view_count" + 1,
      "is_burned" = CASE WHEN ${final} THEN true ELSE false END,
      "ciphertext" = CASE WHEN ${final} THEN '' ELSE "ciphertext" END,
      "nonce" = CASE WHEN ${final} THEN '' ELSE "nonce" END,
      "salt" = CASE WHEN ${final} THEN NULL ELSE "salt" END,
      "kdf_params" = CASE WHEN ${final} THEN NULL ELSE "kdf_params" END,
      "wrapped_key" = CASE WHEN ${final} THEN NULL ELSE "wrapped_key" END
    WHERE "id" = ${id}
      AND "is_burned" = false
      AND "view_count" < ${maxViews}
    RETURNING "view_count", "is_burned"
  `

  const row = rows[0]
  if (!row) {
    return null
  }

  return {
    view_count: Number(row.view_count),
    is_burned:
      typeof row.is_burned === 'boolean' ? row.is_burned : Number(row.is_burned) === 1,
  }
}
