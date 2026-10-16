import { getPrisma } from './db.js'
import { ensureColumns, ensurePartialUniqueIndex, timestampType } from './schema-utils.js'

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

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "deviceCode" (
      "id" TEXT NOT NULL PRIMARY KEY,
      "deviceCode" TEXT NOT NULL UNIQUE,
      "userCode" TEXT NOT NULL UNIQUE,
      "userId" TEXT,
      "expiresAt" TIMESTAMP NOT NULL,
      "status" TEXT NOT NULL,
      "lastPolledAt" TIMESTAMP,
      "pollingInterval" INTEGER,
      "clientId" TEXT,
      "scope" TEXT,
      FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
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
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "deviceCode_userId_idx" ON "deviceCode"("userId")'
  )
  await prisma.$executeRawUnsafe(
    'CREATE INDEX IF NOT EXISTS "deviceCode_status_expiresAt_idx" ON "deviceCode"("status", "expiresAt")'
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

  await ensureColumns('OwnedShare', [
    ['max_views', 'INTEGER'],
    ['recipient_fingerprint', 'TEXT'],
    ['recipient_agent_id', 'TEXT'],
    ['created_via_token_id', 'TEXT'],
  ])
}

// The user foreign key matches the one Prisma Migrate creates (name and
// ON UPDATE CASCADE), so a table created here first doesn't drift on Postgres.
function userForeignKey(table: string) {
  return `CONSTRAINT "${table}_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE`
}

async function ensureAgentReadyTables() {
  const prisma = getPrisma()
  const timestamp = timestampType()

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "ApiToken" (
      "id" TEXT NOT NULL,
      "user_id" TEXT NOT NULL,
      "name" TEXT NOT NULL,
      "token_prefix" TEXT NOT NULL,
      "token_hash" TEXT NOT NULL,
      "scopes" TEXT NOT NULL,
      "agent_id" TEXT,
      "created_at" ${timestamp} NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" ${timestamp},
      "last_used_at" ${timestamp},
      "revoked_at" ${timestamp},
      CONSTRAINT "ApiToken_pkey" PRIMARY KEY ("id"),
      ${userForeignKey('ApiToken')}
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "AgentIdentity" (
      "id" TEXT NOT NULL,
      "user_id" TEXT NOT NULL,
      "kind" TEXT NOT NULL DEFAULT 'agent',
      "name" TEXT NOT NULL,
      "public_key" TEXT NOT NULL,
      "fingerprint" TEXT NOT NULL,
      "created_at" ${timestamp} NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "last_used_at" ${timestamp},
      "revoked_at" ${timestamp},
      CONSTRAINT "AgentIdentity_pkey" PRIMARY KEY ("id"),
      ${userForeignKey('AgentIdentity')}
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "SecretRequest" (
      "id" TEXT NOT NULL,
      "code" TEXT NOT NULL,
      "user_id" TEXT NOT NULL,
      "requester_agent_id" TEXT NOT NULL,
      "requester_token_id" TEXT,
      "name" TEXT NOT NULL,
      "reason" TEXT,
      "accept" TEXT NOT NULL,
      "public_key" TEXT NOT NULL,
      "fingerprint" TEXT NOT NULL,
      "poll_token_hash" TEXT NOT NULL,
      "poll_interval" INTEGER NOT NULL DEFAULT 3,
      "last_polled_at" ${timestamp},
      "status" TEXT NOT NULL,
      "response_kind" TEXT,
      "response_ciphertext" TEXT,
      "response_nonce" TEXT,
      "response_wrapped_key" TEXT,
      "response_size" INTEGER,
      "fulfilled_by_user_id" TEXT,
      "created_at" ${timestamp} NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "expires_at" ${timestamp} NOT NULL,
      "opened_at" ${timestamp},
      "fulfilled_at" ${timestamp},
      "delivered_at" ${timestamp},
      "acked_at" ${timestamp},
      "closed_at" ${timestamp},
      CONSTRAINT "SecretRequest_pkey" PRIMARY KEY ("id"),
      ${userForeignKey('SecretRequest')}
    )
  `)

  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS "AuditEvent" (
      "id" TEXT NOT NULL,
      "user_id" TEXT NOT NULL,
      "subject_type" TEXT NOT NULL,
      "subject_id" TEXT,
      "slug" TEXT,
      "event" TEXT NOT NULL,
      "actor_kind" TEXT NOT NULL,
      "actor_token_id" TEXT,
      "actor_agent_id" TEXT,
      "client" TEXT,
      "ip_prefix" TEXT,
      "details" TEXT,
      "created_at" ${timestamp} NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id"),
      ${userForeignKey('AuditEvent')}
    )
  `)

  for (const statement of [
    'CREATE UNIQUE INDEX IF NOT EXISTS "ApiToken_token_hash_key" ON "ApiToken"("token_hash")',
    'CREATE INDEX IF NOT EXISTS "ApiToken_user_id_created_at_idx" ON "ApiToken"("user_id", "created_at")',
    'CREATE UNIQUE INDEX IF NOT EXISTS "AgentIdentity_fingerprint_key" ON "AgentIdentity"("fingerprint")',
    'CREATE UNIQUE INDEX IF NOT EXISTS "SecretRequest_code_key" ON "SecretRequest"("code")',
    'CREATE INDEX IF NOT EXISTS "SecretRequest_user_id_created_at_idx" ON "SecretRequest"("user_id", "created_at")',
    'CREATE INDEX IF NOT EXISTS "SecretRequest_status_expires_at_idx" ON "SecretRequest"("status", "expires_at")',
    'CREATE INDEX IF NOT EXISTS "AuditEvent_user_id_created_at_idx" ON "AuditEvent"("user_id", "created_at")',
    'CREATE INDEX IF NOT EXISTS "AuditEvent_subject_id_created_at_idx" ON "AuditEvent"("subject_id", "created_at")',
  ]) {
    await prisma.$executeRawUnsafe(statement)
  }

  // An agent name is unique per account among agents that are not revoked.
  await ensurePartialUniqueIndex(
    'AgentIdentity_user_id_name_active_key',
    'AgentIdentity',
    ['user_id', 'name'],
    'revoked_at IS NULL'
  )
}

export async function ensureAccountSystemSchema() {
  if (schemaEnsured) {
    return
  }

  await ensureAuthTables()
  await ensureOwnedShareTable()
  await ensureAgentReadyTables()
  schemaEnsured = true
}
