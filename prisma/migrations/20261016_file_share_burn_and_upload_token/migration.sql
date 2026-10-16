-- AlterTable
-- IF NOT EXISTS: the server also adds these columns at startup, which can run before migrate deploy.
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "burn_after_read" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "is_burned" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "upload_token_hash" TEXT;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "download_grant_hash" TEXT;
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "download_grant_expires_at" TIMESTAMP(3);
ALTER TABLE "FileShare" ADD COLUMN IF NOT EXISTS "burned_at" TIMESTAMP(3);
