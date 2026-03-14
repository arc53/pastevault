import { getPrisma } from './db.js'

let schemaEnsured = false

async function ensureAuthTables() {
  const prisma = getPrisma()

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "user" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "name" TEXT NOT NULL,
      "email" TEXT NOT NULL UNIQUE,
      "emailVerified" BOOLEAN NOT NULL DEFAULT false,
      "image" TEXT,
      "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "username" TEXT UNIQUE,
      "displayUsername" TEXT
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "session" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "expiresAt" TIMESTAMP NOT NULL,
      "token" TEXT NOT NULL UNIQUE,
      "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "ipAddress" TEXT,
      "userAgent" TEXT,
      "userId" TEXT NOT NULL,
      FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "account" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "accountId" TEXT NOT NULL,
      "providerId" TEXT NOT NULL,
      "userId" TEXT NOT NULL,
      "accessToken" TEXT,
      "refreshToken" TEXT,
      "idToken" TEXT,
      "accessTokenExpiresAt" TIMESTAMP,
      "refreshTokenExpiresAt" TIMESTAMP,
      "scope" TEXT,
      "password" TEXT,
      "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "verification" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "identifier" TEXT NOT NULL,
      "value" TEXT NOT NULL,
      "expiresAt" TIMESTAMP NOT NULL,
      "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "session_userId_idx" ON "session"("userId")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "account_userId_idx" ON "account"("userId")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "verification_identifier_idx" ON "verification"("identifier")'
  )
}

async function ensureOwnedShareTable() {
  const prisma = getPrisma()

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "OwnedShare" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "user_id" TEXT NOT NULL,
      "share_type" TEXT NOT NULL,
      "resource_id" TEXT NOT NULL,
      "slug" TEXT NOT NULL,
      "status" TEXT NOT NULL,
      "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" TIMESTAMP,
      "deleted_at" TIMESTAMP,
      "first_viewed_at" TIMESTAMP,
      "last_viewed_at" TIMESTAMP,
      "view_count" INTEGER NOT NULL DEFAULT 0,
      "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
      "file_count" INTEGER,
      "total_size_bytes" TEXT,
      "is_password_protected" BOOLEAN NOT NULL DEFAULT false,
      FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE
    )
  `)

  await prisma.$executeRawUnsafe(
    'CREATE UNIQUE INDEX IF NOT EXISTS "OwnedShare_share_type_resource_id_key" ON "OwnedShare"("share_type", "resource_id")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "OwnedShare_share_type_resource_id_idx" ON "OwnedShare"("share_type", "resource_id")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "OwnedShare_user_id_created_at_idx" ON "OwnedShare"("user_id", "created_at")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "OwnedShare_user_id_share_type_idx" ON "OwnedShare"("user_id", "share_type")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "OwnedShare_user_id_status_idx" ON "OwnedShare"("user_id", "status")'
  )
}

export async function ensureAccountSystemSchema() {
  if (schemaEnsured) {
    return
  }

  await ensureAuthTables()
  await ensureOwnedShareTable()
  schemaEnsured = true
}
