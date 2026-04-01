/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { PrismaService } from '../../prisma/prisma.service.js';
import { Injectable } from '@nestjs/common';
import { EncryptionService } from '@omnixys/security';
import { generateSecret, generateURI, verify } from 'otplib';

@Injectable()
export class TotpService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryption: EncryptionService,
  ) {}

  async generateForUser(userId: string, email: string) {
    const secret = generateSecret(); // Base32 (unpadded)
    const encryptedSecret = this.encryption.encrypt(secret);

    await this.prisma.totpCredential.upsert({
      where: { userId },
      update: { encryptedSecret, enabled: false },
      create: { userId, encryptedSecret },
    });

    const uri = generateURI({
      issuer: 'Omnixys',
      label: email,
      secret,
    });

    return {
      uri,
      // Do NOT return secret in production after initial display
    };
  }

  async enable(userId: string, code: string): Promise<boolean> {
    const record = await this.prisma.totpCredential.findUnique({
      where: { userId },
    });

    if (!record) {
      return false;
    }

    const secret = this.encryption.decrypt(record.encryptedSecret);

    const result = await verify({
      secret,
      token: code,
      epochTolerance: 5, // ±30 seconds tolerance
    });

    if (result.valid) {
      await this.prisma.totpCredential.update({
        where: { userId },
        data: { enabled: true },
      });
    }

    return result.valid === true;
  }

  async verifyForUser(userId: string, code: string): Promise<boolean> {
    const record = await this.prisma.totpCredential.findUnique({
      where: { userId },
    });

    if (!record?.enabled) {
      return false;
    }

    const secret = this.encryption.decrypt(record.encryptedSecret);

    const result = await verify({
      secret,
      token: code,
      epochTolerance: 30,
    });

    return result.valid === true;
  }
}
