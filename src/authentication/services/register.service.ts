import { env } from '../../config/env.js';
import { paths } from '../../config/keycloak.js';
import { MfaPreference } from '../../prisma/generated/enums.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationInputException,
  AuthenticationStateException,
  AuthenticationUserAlreadyExistsException,
  AuthenticationPasswordPolicyException,
  AuthenticationUserNotFoundException,
} from '../errors/authentication.error.js';
import { KCSignUpDTO } from '../models/dtos/kc-sign-up.dto.js';
import { SignUpPayload } from '../models/payloads/sign-in.payload.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache';
import type { SignUpTokenPayload } from '@omnixys/contracts';
import { KafkaProducerService, KafkaTopics } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import { EncryptionService } from '@omnixys/security';
import { createTmpUsername, RealmRoleType } from '@omnixys/contracts';
import * as argon2 from 'argon2';

const { SERVICE } = env;

@Injectable()
export class RegisterService extends AuthenticateBaseService {
  constructor(
    logger: OmnixysLogger,
    http: HttpService,
    private readonly producer: KafkaProducerService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
    private prisma: PrismaService,
    private readonly cache: ValkeyService,
    private readonly encryptionService: EncryptionService,
  ) {
    super(logger, http);
  }

  async verifySignup(token: string): Promise<SignUpPayload> {
    return TraceRunner.run('Verify Keycloak SignUp', async () => {
      let authKey: string;
      try {
        const decryptedToken = this.encryptionService.decrypt(token, true);
        ({ authKey } = JSON.parse(decryptedToken) as SignUpTokenPayload);
        if (!authKey) {
          throw new TypeError('authKey is missing');
        }
      } catch (error) {
        throw new AuthenticationStateException('signup-token-invalid', error);
      }

      const raw = await this.cache.get(ValkeyKey.signupVerificationAuth, authKey);
      if (!raw) {
        return { message: 'ALREADY_CONSUMED_OR_EXPIRED' };
      }

      this.logger.debug('Sign-up verification started for authKey:%s', authKey);
      this.logger.trace('Raw sign-up data retrieved from cache: %o', raw);

      const input = JSON.parse(raw) as KCSignUpDTO;
      this.logger.debug('[TRACE] Deserialized securityQuestions shape: %o', input.securityQuestions);

      try {
        const payload = await this.signUp(input, token);

        await this.cache.delete(ValkeyKey.signupVerificationAuth, authKey);
        payload.message = 'OK';
        return payload;
      } catch (error: unknown) {
        this.logger.error('Sign-up verification failed: %s', (error as Error)?.message ?? error, {
          error,
        });

        if (
          error instanceof AuthenticationUserAlreadyExistsException ||
          error instanceof AuthenticationPasswordPolicyException
        ) {
          throw error;
        }

        return { message: 'ALREADY_REGISTERED' };
      }
    });
  }

  async signUp(input: KCSignUpDTO, signUpToken: string): Promise<SignUpPayload> {
    return TraceRunner.run('Keycloak Sign Up', async () => {
      this.logger.debug(
        'User sign-up started: username=%s email=%s firstName=%s lastName=%s passwordDefined=%s passwordLength=%s',
        input.username,
        input.email,
        input.firstName,
        input.lastName,
        !!input.password,
        input.password?.length ?? 0,
      );

      const { firstName, lastName, email, username, password } = input;

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email,
        credentials,
      };

      await this.kcRequest('post', paths.users, {
        data: body,
        headers: await this.adminJsonHeaders(),
      });

      const userId = await this.findUserIdByUsername(username);
      if (!userId) {
        throw new AuthenticationUserNotFoundException(username);
      }

      await this.adminService.assignRealmRoleToUser(userId, RealmRoleType.USER);

      await this.prisma.$transaction(async (tx) => {
        const user = await tx.authUser.create({
          data: {
            id: userId,
            email: input.email,
            username,
            mfaPreference: MfaPreference.SECURITY_QUESTIONS,
          },
        });

        if (input.securityQuestions?.length) {
          if (!this.isValidSecurityQuestions(input.securityQuestions)) {
            this.logger.warn('Malformed securityQuestions detected: %o', input.securityQuestions);
            throw new AuthenticationInputException('security-questions-malformed');
          }

          const hashedQuestions = await Promise.all(
            input.securityQuestions.map(async (q) => ({
              userId: user.id,
              questionId: q.questionId,
              answerHash: await argon2.hash(q.answer, {
                type: argon2.argon2id,
                memoryCost: 2 ** 16,
                timeCost: 3,
                parallelism: 1,
              }),
            })),
          );

          await tx.userSecurityQuestion.createMany({
            data: hashedQuestions,
          });
        }
      });

      const actorId = createTmpUsername(input.firstName, input.lastName);
      await Promise.all([
        this.producer.send({
          topic: KafkaTopics.user.createUser,
          payload: { userId, token: signUpToken },
          meta: {
            service: SERVICE,
            operation: 'Add User ID from Kafka to UserService',
            version: '1',
            type: 'EVENT',
            actorId,
            tenantId: 'omnixys',
          },
        }),

        this.producer.send({
          topic: KafkaTopics.address.createUserAddresses,
          payload: { userId, token: signUpToken },
          meta: {
            service: SERVICE,
            operation: 'create User Addresses',
            version: '1',
            type: 'EVENT',
            actorId,
            tenantId: 'omnixys',
          },
        }),
      ]);

      const token = await this.authService.passwordLogin({ username, password });
      return { userId, token, username, password: '' };
    });
  }

  /**
   * Validates that securityQuestions is an array of objects with questionId and answer.
   * Rejects malformed payloads like [[]] that would cause argon2.hash(undefined).
   */
  private isValidSecurityQuestions(
    questions: Array<{ questionId?: string; answer?: string }>,
  ): boolean {
    if (!Array.isArray(questions)) {
      return false;
    }
    return questions.every(
      (q) =>
        q &&
        typeof q === 'object' &&
        !Array.isArray(q) &&
        typeof q.questionId === 'string' &&
        q.questionId.length > 0 &&
        typeof q.answer === 'string' &&
        q.answer.length > 0,
    );
  }
}
