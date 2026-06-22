/* eslint-disable @typescript-eslint/no-unsafe-enum-comparison */

/* eslint-disable @typescript-eslint/explicit-function-return-type */

import { ResetTokenState } from '../../prisma/generated/client.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationInputException,
  AuthenticationStateException,
} from '../errors/authentication.error.js';
import {
  MfaPreference,
  ResetVerificationResult,
} from '../models/dtos/reset-verification-result.dto.js';
import { CompleteResetInput } from '../models/inputs/complete.reset.input.js';
import { StepUpVerificationInput } from '../models/inputs/stepup-verification-input.js';
import { BackupCodeService } from './backup-code.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { LockoutService } from './lockout.service.js';
// import { MailService } from './mail.service.js';
import { SecurityQuestionService } from './security-question.service.js';
import { TotpService } from './totp.service.js';
import { WebAuthnService } from './web-authn.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import type { ClientContext } from '@omnixys/context';
import { KafkaProducerService, KafkaTopics } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
import { HashService, HmacService, InvalidCredentialsException } from '@omnixys/security';
import { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { randomBytes } from 'crypto';
import { addMinutes } from 'date-fns';

@Injectable()
export class ResetService extends AuthenticateBaseService {
  constructor(
    logger: OmnixysLogger,
    http: HttpService,
    private readonly prisma: PrismaService,
    private readonly argon: HashService,
    private readonly lockout: LockoutService,
    // private readonly mailService: MailService,
    private readonly hmac: HmacService,
    private readonly totpService: TotpService,
    private readonly webAuthnService: WebAuthnService,
    private readonly backupCodeService: BackupCodeService,
    private readonly securityQuestionService: SecurityQuestionService,
    private readonly kafkaProducer: KafkaProducerService,
  ) {
    super(logger, http);
  }

  async requestReset(email: string, context: ClientContext): Promise<void> {
    this.logger.debug('Request Reset password Token');

    this.logger.debug('Check IP Rate Limit');
    await this.lockout.checkIpRateLimit(context?.ip, 'reset-password');

    const user = await this.prisma.authUser.findUnique({ where: { email } });

    if (!user) {
      this.logger.warn('User does not Exist!');
      return;
    }

    await this.lockout.ensureUserNotLocked(user.id);
    this.logger.debug('User Not Locked');

    // 3) optionally invalidate previous tokens to reduce attack surface
    await this.prisma.passwordResetToken.updateMany({
      where: {
        userId: user.id,
        state: {
          notIn: [ResetTokenState.COMPLETED, ResetTokenState.LOCKED, ResetTokenState.EXPIRED],
        },
      },
      data: {
        state: ResetTokenState.EXPIRED,
        usedAt: new Date(),
      },
    });

    // 4) create token
    const rawToken = randomBytes(32).toString('hex');
    const tokenLookupHash = this.hmac.hash(rawToken, 'resetToken');
    const tokenHash = await this.argon.hash(rawToken);

    await this.prisma.passwordResetToken.create({
      data: {
        tokenHash,
        tokenLookupHash,
        expiresAt: addMinutes(new Date(), 15),
        userId: user.id,
        // ip: context.ip, userAgent: context.userAgent (if you add fields)
      },
    });

    this.logger.debug('Password reset notification requested', {
      email: user.email,
      userId: user.id,
    });

    await this.kafkaProducer.send({
      topic: KafkaTopics.notification.sendRequestReset,
      payload: {
        token: rawToken,
        email: user.email,
        username: user.username,
        locale: context.locale ?? 'de-DE',
        device: context.device ?? 'Unkown Device',
        ip: context.ip ?? 'Unkown IP Address',
        location: context.location ?? 'Germany',
      },
      meta: {
        service: 'authentication-service',
        version: '1',
        operation: 'send Request Email to User',
        type: 'EVENT',
      },
    });
  }

  async verifyResetToken(rawToken: string): Promise<ResetVerificationResult> {
    const token = await this.validateAndLoadToken(rawToken);

    if (token.state !== ResetTokenState.ISSUED) {
      throw new AuthenticationStateException('reset-token-state-invalid');
    }

    await this.prisma.passwordResetToken.update({
      where: { id: token.id },
      data: { state: ResetTokenState.TOKEN_VERIFIED },
    });

    return {
      resetId: token.id, // recommended
      mfaRequired: token.user.mfaPreference !== MfaPreference.NONE,
      mfaMethod: token.user.mfaPreference as MfaPreference,
    };
  }

  // 3️⃣ Step-Up (MFA abhängig von User-Präferenz)
  async verifyStepUp(input: StepUpVerificationInput): Promise<void> {
    const token = await this.validateAndLoadToken(input.token);

    // Enforce correct flow order
    if (token.state !== ResetTokenState.TOKEN_VERIFIED) {
      throw new AuthenticationStateException('reset-token-state-invalid');
    }

    // Optional: user lockout check again (defense in depth)
    await this.lockout.ensureUserNotLocked(token.userId);

    try {
      switch (token.user.mfaPreference) {
        case 'NONE': {
          // No step-up required, but keep semantics consistent
          break;
        }

        case 'TOTP': {
          if (!input.code) {
            throw new AuthenticationInputException('totp-code-missing');
          }
          // Should verify against encrypted secret (service handles decrypt internally)
          const ok = await this.totpService.verifyForUser(token.userId, input.code);
          if (!ok) {
            throw new InvalidCredentialsException('Invalid verification code');
          }
          break;
        }

        case 'WEBAUTHN': {
          // input ist der WEBAUTHN-Typ
          const valid = await this.webAuthnService.verifyAuthenticationForUser(
            token.userId,
            input.credentialResponse as AuthenticationResponseJSON,
          );

          if (!valid) {
            throw new InvalidCredentialsException('WebAuthn verification failed');
          }

          // await this.webAuthnService.consumeAuthenticationChallenge(token.userId);

          break;
        }

        case 'BACKUP_CODES': {
          if (!input.code) {
            throw new AuthenticationInputException('backup-code-missing');
          }
          // consume() marks usedAt on success
          const ok = await this.backupCodeService.consume(token.userId, input.code);
          if (!ok) {
            throw new InvalidCredentialsException('Invalid backup code');
          }
          break;
        }

        case 'SECURITY_QUESTIONS': {
          if (!input.answers || input.answers.length === 0) {
            throw new AuthenticationInputException('security-question-answers-missing');
          }
          const ok = await this.securityQuestionService.verifyAnswers(token.userId, input.answers);
          if (!ok) {
            throw new InvalidCredentialsException('Invalid security answers');
          }
          break;
        }

        default: {
          // English comment tailored for VS:
          // Ensure we fail closed if the enum is expanded.
          throw new AuthenticationStateException('mfa-method-unsupported');
        }
      }

      // Step-up succeeded -> transition state
      await this.prisma.passwordResetToken.update({
        where: { id: token.id },
        data: { state: ResetTokenState.STEP_UP_VERIFIED },
      });
    } catch (e) {
      // On any step-up failure: register attempt on token + user
      await this.lockout.registerTokenFailure(token.id);
      await this.lockout.registerUserFailure(token.userId);

      // Re-throw but do NOT leak details
      if (e instanceof AuthenticationInputException) {
        throw e;
      }
      this.logger.error(`Step-up verification failed: ${(e as Error).message}`);
      throw new InvalidCredentialsException('Step-up verification failed');
    }
  }

  async completeReset(input: CompleteResetInput): Promise<void> {
    const token = await this.validateAndLoadToken(input.token);

    // 1️⃣ Enforce correct flow state
    if (token.state !== ResetTokenState.STEP_UP_VERIFIED) {
      throw new AuthenticationStateException('step-up-verification-required');
    }

    // 2️⃣ Optional: enforce password policy locally (length, complexity)
    if (!this.isPasswordValid(input.newPassword)) {
      throw new AuthenticationInputException('password-policy-failed');
    }

    // 3️⃣ Update password in Keycloak
    await this.kcRequest(
      'put',
      `/admin/realms/${process.env.KC_REALM}/users/${token.user.id}/reset-password`,
      {
        data: {
          type: 'password',
          value: input.newPassword,
          temporary: false,
        },
      },
    );

    // 4️⃣ Invalidate all Keycloak sessions
    await this.kcRequest(
      'post',
      `/admin/realms/${process.env.KC_REALM}/users/${token.user.id}/logout`,
    );

    // 5️⃣ Mark this token as completed
    await this.prisma.passwordResetToken.update({
      where: { id: token.id },
      data: {
        state: ResetTokenState.COMPLETED,
        usedAt: new Date(),
      },
    });

    // 6️⃣ Invalidate all other active tokens for this user
    await this.invalidateAllUserTokens(token.userId);

    // 7️⃣ Reset lockout counters
    await this.lockout.resetUserFailures(token.userId);
  }

  // ----- Internal -----
  private async validateAndLoadToken(rawToken: string) {
    const tokenLookupHash = this.hmac.hash(rawToken, 'resetToken');

    const token = await this.prisma.passwordResetToken.findUnique({
      where: { tokenLookupHash },
      include: { user: true },
    });

    if (!token) {
      await this.argon.dummyVerify(); // timing mitigation
      throw new InvalidCredentialsException('Invalid reset token');
    }

    const valid = await this.argon.verify(token.tokenHash, rawToken);
    if (!valid) {
      await this.incrementTokenAttempt(token.id);
      throw new InvalidCredentialsException('Invalid reset token');
    }

    if (token.state === ResetTokenState.LOCKED) {
      throw new AuthenticationStateException('reset-token-locked');
    }

    if (token.state === ResetTokenState.EXPIRED) {
      throw new AuthenticationStateException('reset-token-expired');
    }

    if (token.expiresAt < new Date()) {
      await this.prisma.passwordResetToken.update({
        where: { id: token.id },
        data: { state: ResetTokenState.EXPIRED },
      });
      throw new AuthenticationStateException('reset-token-expired');
    }

    return token;
  }

  private async incrementTokenAttempt(tokenId: string) {
    const token = await this.prisma.passwordResetToken.update({
      where: { id: tokenId },
      data: { attempts: { increment: 1 } },
    });

    if (token.attempts >= 5) {
      await this.prisma.passwordResetToken.update({
        where: { id: tokenId },
        data: { state: ResetTokenState.LOCKED },
      });
    }
  }

  private async invalidateAllUserTokens(userId: string): Promise<void> {
    await this.prisma.passwordResetToken.updateMany({
      where: {
        userId,
        state: {
          notIn: [ResetTokenState.COMPLETED, ResetTokenState.LOCKED, ResetTokenState.EXPIRED],
        },
      },
      data: {
        state: ResetTokenState.LOCKED,
        usedAt: new Date(),
      },
    });
  }

  private isPasswordValid(password: string): boolean {
    // English comment tailored for VS:
    // Enforce minimal local policy; Keycloak still validates its own policy.
    if (password.length < 12) {
      return false;
    }
    if (!/[A-Z]/.test(password)) {
      return false;
    }
    if (!/[a-z]/.test(password)) {
      return false;
    }
    if (!/[0-9]/.test(password)) {
      return false;
    }
    return true;
  }
}
