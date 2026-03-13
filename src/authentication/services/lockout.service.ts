import { PrismaService } from '../../prisma/prisma.service.js';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { TooManyRequestsException } from '@omnixys/contracts';
import { addHours, addMinutes, isAfter } from 'date-fns';

@Injectable()
export class LockoutService {
  private readonly USER_MAX_ATTEMPTS_PER_HOUR = 3;
  private readonly USER_LOCK_DURATION_HOURS = 10;
  private readonly TOKEN_MAX_ATTEMPTS = 5;

  constructor(private readonly prisma: PrismaService) {}

  /* -------------------------------------------------- */
  /* USER LEVEL LOCKOUT                                */
  /* -------------------------------------------------- */

  async ensureUserNotLocked(userId: string): Promise<void> {
    const user = await this.prisma.authUser.findUnique({
      where: { id: userId },
      select: { lockedUntil: true },
    });

    if (!user) {
      return;
    }

    if (user.lockedUntil && isAfter(user.lockedUntil, new Date())) {
      throw new UnauthorizedException({ message: 'Account temporarily locked' });
    }
  }

  async registerUserFailure(userId: string): Promise<void> {
    const user = await this.prisma.authUser.update({
      where: { id: userId },
      data: { failedAttempts: { increment: 1 } },
      select: { failedAttempts: true },
    });

    if (user.failedAttempts >= this.USER_MAX_ATTEMPTS_PER_HOUR) {
      await this.prisma.authUser.update({
        where: { id: userId },
        data: {
          lockedUntil: addHours(new Date(), this.USER_LOCK_DURATION_HOURS),
          failedAttempts: 0,
        },
      });
    }
  }

  async resetUserFailures(userId: string): Promise<void> {
    await this.prisma.authUser.update({
      where: { id: userId },
      data: { failedAttempts: 0 },
    });
  }

  /* -------------------------------------------------- */
  /* TOKEN LEVEL LOCKOUT                               */
  /* -------------------------------------------------- */

  async registerTokenFailure(tokenId: string): Promise<void> {
    const token = await this.prisma.passwordResetToken.update({
      where: { id: tokenId },
      data: { attempts: { increment: 1 } },
      select: { attempts: true },
    });

    if (token.attempts >= this.TOKEN_MAX_ATTEMPTS) {
      await this.prisma.passwordResetToken.update({
        where: { id: tokenId },
        data: {
          locked: true,
          state: 'LOCKED',
        },
      });
    }
  }

  /* -------------------------------------------------- */
  /* IP RATE LIMIT (Optional DB-Based)                 */
  /* -------------------------------------------------- */

  async checkIpRateLimit(ip: string | undefined, type: string): Promise<void> {
    if (!ip) {
      return;
    }

    const key = `${type}:${ip}`;
    const now = new Date();

    const bucket = await this.prisma.rateLimitBucket.findUnique({
      where: { key },
    });

    if (!bucket) {
      await this.prisma.rateLimitBucket.create({
        data: {
          key,
          windowStart: now,
          count: 1,
        },
      });
      return;
    }

    const windowEnd = addMinutes(bucket.windowStart, 60);

    if (isAfter(now, windowEnd)) {
      await this.prisma.rateLimitBucket.update({
        where: { key },
        data: {
          windowStart: now,
          count: 1,
        },
      });
      return;
    }

    if (bucket.count >= this.USER_MAX_ATTEMPTS_PER_HOUR) {
      throw new TooManyRequestsException({ message: 'Too many attempts from this IP' });
    }

    await this.prisma.rateLimitBucket.update({
      where: { key },
      data: { count: { increment: 1 } },
    });
  }
}
