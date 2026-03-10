import {
  PrismaClient,
  MfaPreference,
  SecurityQuestionType,
} from '../src/prisma/generated/client.js';
import { PrismaPg } from '@prisma/adapter-pg';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import 'dotenv/config';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

const memoryCost = Number(process.env.ARGON2_MEMORY ?? 65536);
const timeCost = Number(process.env.ARGON2_TIME ?? 3);
const parallelism = Number(process.env.ARGON2_PARALLELISM ?? 1);
const pepper = process.env.ARGON2_PEPPER ?? '';

const SECURITY_QUESTIONS: { question: string; key: SecurityQuestionType }[] = [
  {
    question: 'Wie hieß Ihr erstes Haustier?',
    key: SecurityQuestionType.FIRST_PET,
  },
  {
    question: 'In welcher Stadt wurden Sie geboren?',
    key: SecurityQuestionType.BIRTH_CITY,
  },
  {
    question: 'Wie lautet der Mädchenname Ihrer Mutter?',
    key: SecurityQuestionType.MOTHER_MAIDEN_NAME,
  },
  {
    question: 'Was war Ihr Lieblingsfach in der Schule?',
    key: SecurityQuestionType.FAVORITE_SCHOOL_SUBJECT,
  },
  {
    question: 'Wie hieß Ihr bester Freund in der Kindheit?',
    key: SecurityQuestionType.CHILDHOOD_BEST_FRIEND,
  },
];
/**
 * Generates random backup codes and hashes them.
 */
async function generateBackupCodes(userId: string, amount = 5) {
  const codes: { codeHash: string; userId: string }[] = [];

  for (let i = 0; i < amount; i++) {
    const raw = randomBytes(4).toString('hex'); // 8 hex chars
    const hash = await argon2.hash(raw, {
      type: argon2.argon2id,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
    });

    console.log(`Backup code for ${userId}:`, raw); // Only for initial seed visibility

    codes.push({
      codeHash: hash,
      userId,
    });
  }

  return codes;
}

async function main() {
  console.log('🌱 Seeding authentication schema...');

  /* =====================================================
     ADMIN
  ===================================================== */

  const admin = await prisma.authUser.upsert({
    where: { email: 'admin@omnixys.com' },
    update: {},
    create: {
      id: 'dde8114c-2637-462a-90b9-413924fa3f55',
      email: 'admin@omnixys.com',
      mfaPreference: MfaPreference.NONE,
    },
  });

  /* =====================================================
     CALEB (Full MFA example)
  ===================================================== */

  const caleb = await prisma.authUser.upsert({
    where: { email: 'caleb-script2@outlook.de' },
    update: {},
    create: {
      id: '694d2e8e-0932-4c8f-a1c4-e300dc235be4',
      email: 'caleb-script2@outlook.de',
      mfaPreference: MfaPreference.TOTP,
    },
  });

  /* =====================================================
     TOTP (disabled initially)
  ===================================================== */

  await prisma.totpCredential.upsert({
    where: { userId: caleb.id },
    update: {},
    create: {
      userId: caleb.id,
      encryptedSecret: 'SEED_PLACEHOLDER_ENCRYPTED_SECRET',
      enabled: false,
    },
  });

  /* =====================================================
     Backup Codes
  ===================================================== */

  const backupCodes = await generateBackupCodes(caleb.id);

  for (const code of backupCodes) {
    await prisma.backupCode.create({ data: code });
  }

  /* =====================================================
     Controlled Security Questions
  ===================================================== */

  const createdQuestions = [];

  for (const question of SECURITY_QUESTIONS) {
    const q = await prisma.securityQuestion.upsert({
      where: { key: question.key },
      update: {},
      create: { question: question.question, key: question.key },
    });

    createdQuestions.push(q);
  }

  // 1️⃣ Create global questions (controlled set)
  const favoriteCompany = await prisma.securityQuestion.upsert({
    where: { question: 'What is your favorite company?' },
    update: {},
    create: {
      question: 'What is your favorite company?',
      key: SecurityQuestionType.FAVOURITE_COMPANY,
    },
  });

  const birthPlace = await prisma.securityQuestion.upsert({
    where: { question: 'When were you born?' },
    update: {},
    create: {
      question: 'When were you born?',
      key: SecurityQuestionType.BIRTH_DATE,
    },
  });

  // 2️⃣ Hash answer
  const answerHash = await argon2.hash('omnixys', {
    type: argon2.argon2id,
    memoryCost,
    timeCost,
    parallelism,
  });

  // 3️⃣ Assign answers to user
  await prisma.userSecurityQuestion.createMany({
    data: [
      {
        userId: caleb.id,
        questionId: favoriteCompany.id,
        answerHash,
      },
      {
        userId: caleb.id,
        questionId: birthPlace.id,
        answerHash,
      },
    ],
  });

  console.log('✅ Authentication seed completed');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
