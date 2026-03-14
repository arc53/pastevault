import { getPrisma } from './db.js'

let schemaEnsured = false

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
      "view_count" INTEGER NOT NULL DEFAULT 0
    )
  `)

  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "Paste_expires_at_idx" ON "Paste"("expires_at")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "Paste_slug_idx" ON "Paste"("slug")'
  )

  schemaEnsured = true
}
