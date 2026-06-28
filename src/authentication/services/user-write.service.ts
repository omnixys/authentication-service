/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import { env } from '../../config/env.js';
import { paths } from '../../config/keycloak.js';
import { MfaPreference } from '../../prisma/generated/client.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationStateException,
  AuthenticationUserNotFoundException,
  GuestSignupException,
} from '../errors/authentication.error.js';
import { KeycloakUser, KeycloakUserPatch } from '../models/dtos/kc-user.dto.js';
import { updatePasswortDTO } from '../models/dtos/update-password.dto.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { toUsers } from '../models/mappers/user.mapper.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { ResetService } from './reset.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { DelayedJobKeys, DelayedJobService, ValkeyKey, ValkeyService } from '@omnixys/cache';
import { ContextAccessor, type ClientContext } from '@omnixys/context';
import { guestAuthKeySchema, guestSignUpTokenPayloadSchema } from '@omnixys/contracts';
import { EventType, KafkaProducerService, KafkaTopics } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import { EncryptionService } from '@omnixys/security';
import { RealmRoleType } from '@omnixys/contracts';
import { randomBytes, randomInt } from 'node:crypto';

const { SERVICE } = env;

export interface SignUpResult {
  userId: string;
  username: string;
  password: string;
  email: string;
}

export interface GuestSignUp {
  users?: SignUpResult[];
  message?: string;
}
export enum VerifyGuestMessage {
  SUCCESS = 'SUCCESS',
  ALREADY_CONSUMED_OR_EXPIRED = 'ALREADY_CONSUMED_OR_EXPIRED',
  INVALID_TOKEN = 'INVALID_TOKEN',
}
/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class UserWriteService extends AuthenticateBaseService {
  constructor(
    omnixysLogger: OmnixysLogger,
    http: HttpService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
    private authenticateReadService: AuthenticateReadService,
    private readonly kafkaProducer: KafkaProducerService,
    private readonly encryptionServie: EncryptionService,
    private readonly cacheService: ValkeyService,
    private readonly prisma: PrismaService,
    private readonly delayedJobService: DelayedJobService,
    private readonly resetService: ResetService,
  ) {
    super(omnixysLogger, http);
  }

  /**
   * Guest signup flow (deterministic & invitee-based)
   */
  async guestSignUp(signUpToken: string, clientInfo: ClientContext): Promise<GuestSignUp> {
    return TraceRunner.run('Sign UP Guest Account', async (): Promise<GuestSignUp> => {
      this.logger.debug('signUp: clientInfo=%o', clientInfo);

      /**
       * 1️⃣ Decrypt token
       */
      let authKey: string;
      try {
        const decryptedToken = this.encryptionServie.decrypt(signUpToken, true);
        ({ authKey } = guestSignUpTokenPayloadSchema.parse(JSON.parse(decryptedToken)));
      } catch (error) {
        throw new GuestSignupException('verification-token-invalid', error);
      }

      /**
       * 2️⃣ Load auth payload
       */
      const raw = await this.cacheService.get(ValkeyKey.guestVerificationAuth, authKey);

      if (!raw) {
        return { message: 'ALREADY_CONSUMED_OR_EXPIRED' };
      }

      try {
        const input = guestAuthKeySchema.parse(JSON.parse(raw));

        /**
         * 🔥 NEW: invitee-based processing
         */
        const invitees = input.invitees ?? [];

        if (!invitees.length) {
          throw new GuestSignupException('invitees-missing');
        }

        const results: SignUpResult[] = [];

        /**
         * 3️⃣ Process ALL invitees (main + plusOnes)
         */
        for (const invitee of invitees) {
          /**
           * Create user
           */
          const user = await this.createGuestUser({
            firstName: invitee.firstName,
            lastName: invitee.lastName,
            email: invitee.email,
            eventEndsAt: input.eventEndsAt,
          });

          results.push(user);

          /**
           * 🔥 Kafka fan-out (deterministic via invitationId)
           */
          await Promise.all([
            this.kafkaProducer.send({
              topic: KafkaTopics.user.createGuest,
              payload: {
                userId: user.userId,
                invitationId: invitee.invitationId,
                token: signUpToken,
                username: user.username,
                email: user.email,
              },
              meta: this.meta(user.userId, 'create guest user'),
            }),

            this.kafkaProducer.send({
              topic: KafkaTopics.event.addRole,
              payload: {
                userId: user.userId,
                invitationId: invitee.invitationId,
                token: signUpToken,
              },
              meta: this.meta(user.userId, 'assign role'),
            }),

            this.kafkaProducer.send({
              topic: KafkaTopics.seat.addGuestId,
              payload: {
                userId: user.userId,
                invitationId: invitee.invitationId,
                token: signUpToken,
              },
              meta: this.meta(user.userId, 'assign seat'),
            }),
          ]);
        }

        /**
         * 4️⃣ Delete token → prevents replay
         */
        await this.cacheService.delete(ValkeyKey.guestVerificationAuth, authKey);

        return { users: results };
      } catch (e: unknown) {
        this.logger.error('Guest sign-up failed', { error: e });
        if (e instanceof GuestSignupException) {
          throw e;
        }
        throw new GuestSignupException('invalid-or-incomplete-state', e);
      }
    });
  }

  /**
   * Creates a single user in Keycloak + DB
   */
  async createGuestUser(data: {
    firstName: string;
    lastName: string;
    email?: string;
    eventEndsAt: Date;
  }): Promise<SignUpResult> {
    /**
     * Generate credentials
     */
    const {
      username,
      email: finalEmail,
      password,
    } = await this.createUsernameAndEmailAndPassword(data);

    /**
     * Create in Keycloak
     */
    await this.kcRequest('post', paths.users, {
      data: {
        username,
        enabled: true,
        firstName: data.firstName,
        lastName: data.lastName,
        email: finalEmail,
        credentials: [
          {
            type: 'password',
            value: password,
            temporary: false,
          },
        ],
      },
      headers: await this.adminJsonHeaders(),
    });

    /**
     * Resolve userId
     */
    const userId = await this.findUserIdByUsername(username);
    if (!userId) {
      throw new AuthenticationUserNotFoundException(username);
    }

    /**
     * Assign role
     */
    await this.adminService.assignRealmRoleToUser(userId, RealmRoleType.GUEST);

    /**
     * Persist locally
     */
    await this.prisma.authUser.create({
      data: {
        id: userId,
        email: finalEmail,
        username,
        mfaPreference: MfaPreference.SECURITY_QUESTIONS,
      },
    });

    const delayMs = Math.max(0, data.eventEndsAt.getTime() - Date.now());

    await this.delayedJobService.schedule({
      type: DelayedJobKeys.user.delete,
      payload: { userId },
      delayMs,
    });

    return {
      userId,
      username,
      password,
      email: finalEmail,
    };
  }

  async createKeycloakUser(data: {
    provider: string;
    providerId: string;
    email: string;
    name?: string;
  }): Promise<string> {
    void this.logger.debug('createKeycloakUser: data=%o', data);

    const body = {
      username: data.name ?? `${data.provider}_${data.providerId}`,
      email: data.email,
      enabled: true,
      emailVerified: true,
      firstName: data.provider,
      lastName: 'User',
      requiredActions: [],
      attributes: {
        provider: data.provider,
        providerId: data.providerId,
      },
    };

    await this.kcRequest('post', paths.users, {
      data: body,
      headers: await this.adminJsonHeaders(),
    });

    // id ermitteln
    const userId = await this.findUserIdByUsername(
      data.name ?? `${data.provider}_${data.providerId}`,
    );
    if (!userId) {
      throw new AuthenticationUserNotFoundException(body.username);
    }

    // Rolle zuweisen
    await this.adminService.assignRealmRoleToUser(userId, RealmRoleType.USER);

    return userId;
  }

  async changePassword({
    userId,
    username,
    oldPassword,
    newPassword,
  }: updatePasswortDTO): Promise<void> {
    // 1) Old password validieren via Token-Endpoint (ROPC)
    await this.authService.passwordLogin({ username, password: oldPassword });

    // 2) Neues Passwort via Admin REST setzen
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(userId)}/reset-password`, {
      data: { type: 'password', value: newPassword, temporary: false },
      headers: await this.adminJsonHeaders(),
    });
  }

  async sendPasswordResetNotification(id: string): Promise<void> {
    const user = await this.authenticateReadService.findById(id);
    if (!user.email) {
      throw new AuthenticationStateException('user-email-missing');
    }
    const client = ContextAccessor.get()?.client;
    await this.resetService.requestReset(user.email, {
      ip: client?.ip,
      userAgent: client?.userAgent,
      device: client?.device?.model ?? client?.device?.type ?? 'Internal service',
      browser: client?.browser?.name ?? 'Unknown browser',
      os: client?.os?.name ?? 'Server',
      location: [client?.location?.city, client?.location?.country].filter(Boolean).join(', '),
      locale: client?.locale === 'en-US' ? 'en-US' : 'de-DE',
    });
  }

  /**
   * Realm-Rolle von User entfernen.
   */
  async removeRealmRoleFromUser(userId: string, roleName: RealmRoleType | string): Promise<void> {
    const role = await this.getRealmRole(roleName);
    await this.kcRequest(
      'delete',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { data: [role] },
    );
  }

  // ---------- Helpers (nur für Write-Service) ----------
  private async createUsernameAndEmailAndPassword(input: {
    firstName: string;
    lastName: string;
    email?: string;
  }): Promise<{ username: string; email: string; password: string }> {
    const base = (input.lastName.slice(0, 2) + input.firstName.slice(0, 2))
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');

    const randomSuffix = randomInt(1000, 10_000).toString();
    const baseUsername = `${base}${randomSuffix}`;

    let username = baseUsername;
    let email = input.email ?? `${username}@omnixys.com`;

    // Max fallback attempts
    for (let i = 0; i < 10; i++) {
      const usernameTaken = await this.userExistsByUsername(username);
      const emailTaken = await this.userExistsByEmail(email);

      if (!usernameTaken && !emailTaken) {
        const password = randomBytes(18).toString('base64url');
        return { username, email, password };
      }

      // FALLBACK
      const suffix = i + 1;

      if (usernameTaken) {
        username = `${baseUsername}-${suffix}`;
      }

      if (emailTaken) {
        const [name, domain] = (input.email ?? `${baseUsername}@omnixys.com`).split('@');
        email = `${name}+${suffix}@${domain}`;
      }
    }

    throw new GuestSignupException('unique-credentials-exhausted');
  }

  /** Check if Keycloak already has a user with this username */
  private async userExistsByUsername(username: string): Promise<boolean> {
    const raw = await this.kcRequest<KeycloakUser[]>('get', paths.users, {
      params: { username, exact: true },
      headers: await this.adminJsonHeaders(),
    });
    const users = toUsers(raw);
    return Array.isArray(users) && users.length > 0;
  }

  /** Check if Keycloak already has a user with this email */
  private async userExistsByEmail(email: string): Promise<boolean> {
    const raw = await this.kcRequest<KeycloakUser[]>('get', paths.users, {
      params: { email, exact: true },
      headers: await this.adminJsonHeaders(),
    });
    const users = toUsers(raw);
    return Array.isArray(users) && users.length > 0;
  }

  async update(id: string, input: UpdateMyProfileInput): Promise<void> {
    const { firstName, lastName, email } = input;
    // 1) Bestehenden User laden (für Merge)
    const kcUser = await this.authenticateReadService.findById(id);

    // 6) KC-User Patch – nur attributes setzen, wenn wir wirklich was schreiben wollen
    const patch: KeycloakUserPatch = {
      firstName: firstName ?? kcUser.firstName,
      lastName: lastName ?? kcUser.lastName,
      email: email ?? kcUser.email,
    };

    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(id)}`, {
      data: patch,
      headers: await this.adminJsonHeaders(),
    });
  }

  /**
   * Standard Kafka metadata builder.
   */
  private meta(
    actorId: string,
    operation: string,
  ): {
    actorId: string;
    tenantId: string;
    service: string;
    operation: string;
    version: string;
    type: EventType;
  } {
    const type: EventType = 'EVENT';
    return {
      actorId,
      tenantId: 'omnixys',
      service: SERVICE,
      operation,
      version: '1',
      type,
    };
  }
}
