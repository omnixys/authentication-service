-- CreateEnum
CREATE TYPE "mfa_preference" AS ENUM ('NONE', 'TOTP', 'WEBAUTHN', 'BACKUP_CODES', 'SECURITY_QUESTIONS');

-- CreateEnum
CREATE TYPE "reset_token_state" AS ENUM ('ISSUED', 'TOKEN_VERIFIED', 'STEP_UP_VERIFIED', 'COMPLETED', 'LOCKED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "security_question_key" AS ENUM ('FIRST_PET', 'BIRTH_CITY', 'MOTHER_MAIDEN_NAME', 'FAVORITE_SCHOOL_SUBJECT', 'CHILDHOOD_BEST_FRIEND', 'FAVOURITE_COMPANY', 'BIRTH_DATE');

-- CreateTable
CREATE TABLE "auth_user" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "mfa_preference" "mfa_preference" NOT NULL DEFAULT 'NONE',
    "failed_attempts" INTEGER NOT NULL DEFAULT 0,
    "locked_until" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatet_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "auth_user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "totp_credential" (
    "id" TEXT NOT NULL,
    "encrypted_secret" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "user_id" TEXT NOT NULL,

    CONSTRAINT "totp_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "web_auth_n_credentials" (
    "id" TEXT NOT NULL,
    "credential_id" TEXT NOT NULL,
    "public_key" TEXT NOT NULL,
    "counter" INTEGER NOT NULL,
    "device_type" TEXT NOT NULL,
    "backed_up" BOOLEAN NOT NULL,
    "transports" TEXT,
    "nickname" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMP(3),
    "revoked_at" TIMESTAMP(3),
    "user_id" TEXT NOT NULL,

    CONSTRAINT "web_auth_n_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_code" (
    "id" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used_at" TIMESTAMP(3),
    "user_id" TEXT NOT NULL,

    CONSTRAINT "backup_code_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_question" (
    "id" TEXT NOT NULL,
    "key" "security_question_key" NOT NULL,
    "question" TEXT NOT NULL,

    CONSTRAINT "security_question_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_security_question" (
    "id" TEXT NOT NULL,
    "answer_hash" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,

    CONSTRAINT "user_security_question_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_token" (
    "id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "token_lookup_hash" TEXT NOT NULL,
    "state" "reset_token_state" NOT NULL DEFAULT 'ISSUED',
    "expires_at" TIMESTAMP(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "locked" BOOLEAN NOT NULL DEFAULT false,
    "used_at" TIMESTAMP(3),
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_reset_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rate_limit_bucket" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "window_start" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL,
    "locked_until" TIMESTAMP(3),

    CONSTRAINT "rate_limit_bucket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnownDevice" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "first_seen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KnownDevice_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LoginHistory" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    "country" TEXT,
    "city" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LoginHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OAuthAccount" (
    "id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "provider_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,

    CONSTRAINT "OAuthAccount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "auth_user_email_key" ON "auth_user"("email");

-- CreateIndex
CREATE UNIQUE INDEX "auth_user_username_key" ON "auth_user"("username");

-- CreateIndex
CREATE INDEX "auth_user_email_idx" ON "auth_user"("email");

-- CreateIndex
CREATE INDEX "auth_user_username_idx" ON "auth_user"("username");

-- CreateIndex
CREATE UNIQUE INDEX "totp_credential_user_id_key" ON "totp_credential"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "web_auth_n_credentials_credential_id_key" ON "web_auth_n_credentials"("credential_id");

-- CreateIndex
CREATE INDEX "web_auth_n_credentials_user_id_idx" ON "web_auth_n_credentials"("user_id");

-- CreateIndex
CREATE INDEX "backup_code_user_id_idx" ON "backup_code"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "security_question_key_key" ON "security_question"("key");

-- CreateIndex
CREATE UNIQUE INDEX "security_question_question_key" ON "security_question"("question");

-- CreateIndex
CREATE INDEX "user_security_question_user_id_idx" ON "user_security_question"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_security_question_user_id_questionId_key" ON "user_security_question"("user_id", "questionId");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_token_token_lookup_hash_key" ON "password_reset_token"("token_lookup_hash");

-- CreateIndex
CREATE INDEX "password_reset_token_user_id_idx" ON "password_reset_token"("user_id");

-- CreateIndex
CREATE INDEX "password_reset_token_expires_at_idx" ON "password_reset_token"("expires_at");

-- CreateIndex
CREATE INDEX "password_reset_token_token_lookup_hash_expires_at_idx" ON "password_reset_token"("token_lookup_hash", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "rate_limit_bucket_key_key" ON "rate_limit_bucket"("key");

-- CreateIndex
CREATE UNIQUE INDEX "rate_limit_bucket_key_window_start_key" ON "rate_limit_bucket"("key", "window_start");

-- CreateIndex
CREATE INDEX "KnownDevice_user_id_idx" ON "KnownDevice"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "KnownDevice_user_id_fingerprint_key" ON "KnownDevice"("user_id", "fingerprint");

-- CreateIndex
CREATE INDEX "LoginHistory_user_id_createdAt_idx" ON "LoginHistory"("user_id", "createdAt");

-- CreateIndex
CREATE INDEX "LoginHistory_user_id_idx" ON "LoginHistory"("user_id");

-- CreateIndex
CREATE INDEX "OAuthAccount_user_id_idx" ON "OAuthAccount"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthAccount_provider_provider_id_key" ON "OAuthAccount"("provider", "provider_id");

-- AddForeignKey
ALTER TABLE "totp_credential" ADD CONSTRAINT "totp_credential_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "web_auth_n_credentials" ADD CONSTRAINT "web_auth_n_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_code" ADD CONSTRAINT "backup_code_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_security_question" ADD CONSTRAINT "user_security_question_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_security_question" ADD CONSTRAINT "user_security_question_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "security_question"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "password_reset_token" ADD CONSTRAINT "password_reset_token_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "KnownDevice" ADD CONSTRAINT "KnownDevice_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LoginHistory" ADD CONSTRAINT "LoginHistory_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthAccount" ADD CONSTRAINT "OAuthAccount_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth_user"("id") ON DELETE CASCADE ON UPDATE CASCADE;
