-- Agent-ready: view limits, sealed-share recipients, API tokens, agent identities,
-- secret requests and the audit log.
-- Every statement is idempotent: the server also creates these columns, tables,
-- indexes and foreign keys at startup, which can run before migrate deploy.

-- AlterTable
ALTER TABLE "Paste" ADD COLUMN IF NOT EXISTS "max_views" INTEGER;
ALTER TABLE "Paste" ADD COLUMN IF NOT EXISTS "recipient_agent_id" TEXT;
ALTER TABLE "Paste" ADD COLUMN IF NOT EXISTS "recipient_fingerprint" TEXT;
ALTER TABLE "Paste" ADD COLUMN IF NOT EXISTS "recipient_user_id" TEXT;
ALTER TABLE "Paste" ADD COLUMN IF NOT EXISTS "wrapped_key" TEXT;

-- AlterTable
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "max_views" INTEGER;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "recipient_agent_id" TEXT;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "recipient_fingerprint" TEXT;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "recipient_user_id" TEXT;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "wrapped_key" TEXT;

-- AlterTable
ALTER TABLE "OwnedShare" ADD COLUMN IF NOT EXISTS "created_via_token_id" TEXT;
ALTER TABLE "OwnedShare" ADD COLUMN IF NOT EXISTS "max_views" INTEGER;
ALTER TABLE "OwnedShare" ADD COLUMN IF NOT EXISTS "recipient_agent_id" TEXT;
ALTER TABLE "OwnedShare" ADD COLUMN IF NOT EXISTS "recipient_fingerprint" TEXT;

-- CreateTable
CREATE TABLE IF NOT EXISTS "ApiToken" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "token_prefix" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "scopes" TEXT NOT NULL,
    "agent_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3),
    "last_used_at" TIMESTAMP(3),
    "revoked_at" TIMESTAMP(3),

    CONSTRAINT "ApiToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE IF NOT EXISTS "AgentIdentity" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'agent',
    "name" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMP(3),
    "revoked_at" TIMESTAMP(3),

    CONSTRAINT "AgentIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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
    "last_polled_at" TIMESTAMP(3),
    "status" TEXT NOT NULL,
    "response_kind" TEXT,
    "response_ciphertext" TEXT,
    "response_nonce" TEXT,
    "response_wrapped_key" TEXT,
    "response_size" INTEGER,
    "fulfilled_by_user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "opened_at" TIMESTAMP(3),
    "fulfilled_at" TIMESTAMP(3),
    "delivered_at" TIMESTAMP(3),
    "acked_at" TIMESTAMP(3),
    "closed_at" TIMESTAMP(3),

    CONSTRAINT "SecretRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
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
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "ApiToken_token_hash_key" ON "ApiToken"("token_hash");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "ApiToken_user_id_created_at_idx" ON "ApiToken"("user_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "AgentIdentity_fingerprint_key" ON "AgentIdentity"("fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "AgentIdentity_user_id_name_active_key" ON "AgentIdentity"("user_id", "name") WHERE (revoked_at IS NULL);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "SecretRequest_code_key" ON "SecretRequest"("code");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "SecretRequest_user_id_created_at_idx" ON "SecretRequest"("user_id", "created_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "SecretRequest_status_expires_at_idx" ON "SecretRequest"("status", "expires_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "AuditEvent_user_id_created_at_idx" ON "AuditEvent"("user_id", "created_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "AuditEvent_subject_id_created_at_idx" ON "AuditEvent"("subject_id", "created_at");

-- AddForeignKey
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ApiToken_user_id_fkey' AND conrelid = '"ApiToken"'::regclass) THEN
        ALTER TABLE "ApiToken" ADD CONSTRAINT "ApiToken_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;

-- AddForeignKey
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'AgentIdentity_user_id_fkey' AND conrelid = '"AgentIdentity"'::regclass) THEN
        ALTER TABLE "AgentIdentity" ADD CONSTRAINT "AgentIdentity_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;

-- AddForeignKey
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'SecretRequest_user_id_fkey' AND conrelid = '"SecretRequest"'::regclass) THEN
        ALTER TABLE "SecretRequest" ADD CONSTRAINT "SecretRequest_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;

-- AddForeignKey
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'AuditEvent_user_id_fkey' AND conrelid = '"AuditEvent"'::regclass) THEN
        ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
    END IF;
END $$;
