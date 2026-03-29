-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "Paste" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "ciphertext" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "salt" TEXT,
    "kdf_params" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3),
    "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
    "is_burned" BOOLEAN NOT NULL DEFAULT false,
    "view_count" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "Paste_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FileShare" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "manifest_ciphertext" TEXT,
    "manifest_nonce" TEXT,
    "salt" TEXT,
    "kdf_params" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3),
    "is_complete" BOOLEAN NOT NULL DEFAULT false,
    "view_count" INTEGER NOT NULL DEFAULT 0,
    "file_count" INTEGER NOT NULL DEFAULT 0,
    "total_size_bytes" TEXT NOT NULL DEFAULT '0',

    CONSTRAINT "FileShare_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "username" TEXT,
    "displayUsername" TEXT,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT NOT NULL,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account" (
    "id" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "idToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMP(3),
    "refreshTokenExpiresAt" TIMESTAMP(3),
    "scope" TEXT,
    "password" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "verification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OwnedShare" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "share_type" TEXT NOT NULL,
    "resource_id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3),
    "deleted_at" TIMESTAMP(3),
    "first_viewed_at" TIMESTAMP(3),
    "last_viewed_at" TIMESTAMP(3),
    "view_count" INTEGER NOT NULL DEFAULT 0,
    "burn_after_read" BOOLEAN NOT NULL DEFAULT false,
    "file_count" INTEGER,
    "total_size_bytes" TEXT,
    "is_password_protected" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "OwnedShare_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Paste_slug_key" ON "Paste"("slug");

-- CreateIndex
CREATE INDEX "Paste_expires_at_idx" ON "Paste"("expires_at");

-- CreateIndex
CREATE INDEX "Paste_slug_idx" ON "Paste"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "FileShare_slug_key" ON "FileShare"("slug");

-- CreateIndex
CREATE INDEX "FileShare_expires_at_idx" ON "FileShare"("expires_at");

-- CreateIndex
CREATE INDEX "FileShare_slug_idx" ON "FileShare"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE UNIQUE INDEX "user_username_key" ON "user"("username");

-- CreateIndex
CREATE INDEX "session_userId_idx" ON "session"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "session_token_key" ON "session"("token");

-- CreateIndex
CREATE INDEX "account_userId_idx" ON "account"("userId");

-- CreateIndex
CREATE INDEX "verification_identifier_idx" ON "verification"("identifier");

-- CreateIndex
CREATE INDEX "OwnedShare_share_type_resource_id_idx" ON "OwnedShare"("share_type", "resource_id");

-- CreateIndex
CREATE INDEX "OwnedShare_user_id_created_at_idx" ON "OwnedShare"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "OwnedShare_user_id_share_type_idx" ON "OwnedShare"("user_id", "share_type");

-- CreateIndex
CREATE INDEX "OwnedShare_user_id_status_idx" ON "OwnedShare"("user_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "OwnedShare_share_type_resource_id_key" ON "OwnedShare"("share_type", "resource_id");

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account" ADD CONSTRAINT "account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OwnedShare" ADD CONSTRAINT "OwnedShare_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

