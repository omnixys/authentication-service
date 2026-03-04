/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { paths } from '../../config/keycloak.js';
import { KafkaProducerService } from '../../kafka/kafka-producer.service.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { MfaPreference } from '../../prisma/generated/enums.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { ValkeyService } from '../../valkey/valkey.service.js';
import { KCSignUpDTO } from '../models/dtos/kc-sign-up.dto.js';
import { RealmRole } from '../models/enums/role.enum.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { SignUpPayload } from '@/authentication/models/payloads/sign-in.payload.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException } from '@nestjs/common';
import * as argon2 from 'argon2';

@Injectable()
export class RegisterService extends AuthenticateBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly kafka: KafkaProducerService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
    private prisma: PrismaService,
    private readonly valkey: ValkeyService,
  ) {
    super(logger, trace, http);
  }

  async verifySignup(token: string): Promise<SignUpPayload> {
    const key = `verification:signup:auth:${token}`;

    const raw = await this.valkey.client.get(key);
    if (!raw) {
      return { message: 'ALREADY_CONSUMED_OR_EXPIRED' };
    }

    const input = JSON.parse(raw) as KCSignUpDTO;

    try {
      // Call UserService
      const payload = await this.signUp(input, token);

      // Delete key
      await this.valkey.client.del(key);
      payload.message = 'OK';
      return payload;
    } catch (e: any) {
      this.logger.debug(e);
      return { message: 'ALREADY_REGISTERED' };
    }
  }

  async signUp(input: KCSignUpDTO, valkeyToken?: string): Promise<SignUpPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
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
      await this.adminService.assignRealmRoleToUser(userId, RealmRole.USER);

      const sc = span.spanContext();

      return this.prisma.$transaction(async (tx) => {
        /* ------------------------------------------------------------
         * 1. User (technical root)
         * ------------------------------------------------------------ */
        const user = await tx.authUser.create({
          data: {
            id: userId,
            email: input.email,
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

        void this.kafka.addUserId(
          { newId: userId, oldId: input.id, token: valkeyToken },
          'authentication.userSignUp',
          {
            traceId: sc.traceId,
            spanId: sc.spanId,
          },
        );

        const token = await this.authService.login({ username, password });
        return { userId, token };
      });
    });
  }
}
