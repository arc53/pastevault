-- CreateTable
CREATE TABLE "deviceCode" (
    "id" TEXT NOT NULL,
    "deviceCode" TEXT NOT NULL,
    "userCode" TEXT NOT NULL,
    "userId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL,
    "lastPolledAt" TIMESTAMP(3),
    "pollingInterval" INTEGER,
    "clientId" TEXT,
    "scope" TEXT,

    CONSTRAINT "deviceCode_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "deviceCode_deviceCode_key" ON "deviceCode"("deviceCode");

-- CreateIndex
CREATE UNIQUE INDEX "deviceCode_userCode_key" ON "deviceCode"("userCode");

-- CreateIndex
CREATE INDEX "deviceCode_status_expiresAt_idx" ON "deviceCode"("status", "expiresAt");

-- CreateIndex
CREATE INDEX "deviceCode_userId_idx" ON "deviceCode"("userId");

-- AddForeignKey
ALTER TABLE "deviceCode" ADD CONSTRAINT "deviceCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
