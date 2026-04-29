/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { env } from '../../config/env.js';
import { paths } from '../../config/keycloak.js';
import { MfaPreference } from '../../prisma/generated/enums.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { KCSignUpDTO } from '../models/dtos/kc-sign-up.dto.js';
import { SignUpPayload } from '../models/payloads/sign-in.payload.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache';
import { KafkaProducerService, KafkaTopics } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import { EncryptionService } from '@omnixys/security';
import { createTmpUsername, RealmRoleType, SignUpTokenPayload } from '@omnixys/shared';
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
      const key = `verification:signup:auth:${token}`;

      const decryptedToken = this.encryptionService.decrypt(token, true);
      const { authKey } = JSON.parse(decryptedToken) as SignUpTokenPayload;

      const raw = await this.cache.get(ValkeyKey.signupVerificationAuth, authKey);
      if (!raw) {
        return { message: 'ALREADY_CONSUMED_OR_EXPIRED' };
      }

      const input = JSON.parse(raw) as KCSignUpDTO;

      try {
        // Call UserService
        const payload = await this.signUp(input, token);

        // Delete key
        await this.cache.client.del(key);
        payload.message = 'OK';
        return payload;
      } catch (e: any) {
        this.logger.error(e);
        return { message: 'ALREADY_REGISTERED' };
      }
    });
  }

  async signUp(input: KCSignUpDTO, signUpToken: string): Promise<SignUpPayload> {
    return TraceRunner.run('Keycloak Sign Up', async () => {
      void this.logger.debug('signUp: input=%o', input);

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

      // id ermitteln
      const userId = await this.findUserIdByUsername(username);
      if (!userId) {
        throw new NotFoundException('User id could not be resolved after signUp');
      }

      // Rolle zuweisen
      await this.adminService.assignRealmRoleToUser(userId, RealmRoleType.USER);

      return this.prisma.$transaction(async (tx) => {
        /* ------------------------------------------------------------
         * 1. User (technical root)
         * ------------------------------------------------------------ */
        const user = await tx.authUser.create({
          data: {
            id: userId,
            email: input.email,
            username,
            mfaPreference: MfaPreference.SECURITY_QUESTIONS,
          },
        });

        /* ------------------------------------------------------------
         * 2. SecurityQuestions (optional)
         * ------------------------------------------------------------ */
        if (input.securityQuestions?.length) {
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

        void this.producer.send({
          topic: KafkaTopics.user.createUser,
          payload: { userId, token: signUpToken },
          meta: {
            service: SERVICE,
            operation: 'Add User ID from Kafka to UserService',
            version: '1',
            type: 'EVENT',
            actorId: createTmpUsername(input.lastName, input.lastName),
            tenantId: 'omnixys',
          },
        });

        void this.producer.send({
          topic: KafkaTopics.address.createUserAddresses,
          payload: { userId, token: signUpToken },
          meta: {
            service: SERVICE,
            operation: 'create User Addresses',
            version: '1',
            type: 'EVENT',
            actorId: createTmpUsername(input.lastName, input.lastName),
            tenantId: 'omnixys',
          },
        });

        const token = await this.authService.passwordLogin({ username, password });
        return { userId, token, username, password: '' };
      });
    });
  }
}
