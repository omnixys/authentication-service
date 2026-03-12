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

import { paths } from '../../config/keycloak.js';
import { KafkaProducerService } from '../../kafka/kafka-producer.service.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { KeycloakUser, KeycloakUserPatch } from '../models/dtos/kc-user.dto.js';
import { GuestSignUpDTO } from '../models/dtos/sign-up.dto.js';
import { updatePasswortDTO } from '../models/dtos/update-password.dto.js';
import { UserSignUpInput } from '../models/inputs/sign-up.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { toUsers } from '../models/mappers/user.mapper.js';
import { SignUpPayload } from '../models/payloads/sign-in.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { RealmRole } from '@omnixys/contracts';

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
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly kafka: KafkaProducerService,
    private authService: AuthWriteService,
    private adminService: AdminWriteService,
    private authenticateReadService: AuthenticateReadService,
  ) {
    super(logger, trace, http);
  }

  /**
   * User anlegen (mit invitationId/phoneNumber Attributen) + Rolle + Kafka-Events.
   */
  async guestSignUp(input: GuestSignUpDTO): Promise<SignUpPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
      void this.logger.debug('signUp: input=%o', input);

      const { firstName, lastName, email, invitationId, phoneNumbers, eventId, seatId, actorId } =
        input;

      const {
        username,
        email: finalEmail,
        password,
      } = await this.createUsernameAndEmailAndPassword({
        firstName,
        lastName,
        email,
      });

      const credentials: Array<Record<string, string | undefined | boolean>> = [
        { type: 'password', value: password, temporary: false },
      ];

      const body = {
        username,
        enabled: true,
        firstName,
        lastName,
        email: finalEmail,
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
      void this.kafka.createUser(
        {
          id: userId,
          username,
          firstName,
          lastName,
          email: finalEmail,
          phoneNumbers,
          invitationId,
        },
        'authentication.guestSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );

      void this.kafka.notifyUser(
        {
          userId,
          username,
          password,
          invitationId,
          firstName,
          lastName,
        },
        'authentication.notifyUser',
        { traceId: sc.traceId, spanId: sc.spanId },
      );

      void this.kafka.addEventRole(
        {
          userId,
          eventId,
          actorId: actorId ?? '0',
        },
        'authentication.addEventRole',
        { traceId: sc.traceId, spanId: sc.spanId },
      );

      if (seatId && actorId) {
        void this.kafka.createTicket(
          {
            eventId,
            invitationId,
            guestProfileId: userId,
            seatId,
            actorId,
          },
          'authentication.createTicket',
          { traceId: sc.traceId, spanId: sc.spanId },
        );
      }

      console.debug({ userId, username, password });
      return { userId, username, password };
    });
  }

  async userSignUp(input: UserSignUpInput): Promise<TokenPayload> {
    return this.withSpan('authentication.signUp', async (span) => {
      void this.logger.debug('signUp: input=%o', input);

      const { firstName, lastName, email, username, password, phoneNumbers } = input;

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

      void this.kafka.createUser(
        { id: userId, username, firstName, lastName, email, phoneNumbers },
        'authentication.userSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );
      // TODO kafka nachrichten implementieren

      const token = await this.authService.login({ username, password });
      return token;

      // return { userId, username, password };
    });
  }

  async createKeycloakUser(data: {
    provider: string;
    providerId: string;
    email: string;
    name?: string;
  }): Promise<string> {
    return this.withSpan('authentication.signUp', async (span) => {
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
        throw new NotFoundException('User id could not be resolved after signUp');
      }

      // Rolle zuweisen
      await this.adminService.assignRealmRoleToUser(userId, RealmRole.USER);

      const sc = span.spanContext();

      void this.kafka.createUser(
        {
          id: userId,
          username: data.name ?? `${data.provider}_${data.providerId}`,
          firstName: data.name ?? 'GitHub',
          lastName: 'User',
          email: data.email,
        },
        'authentication.userSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );

      if (!userId) {
        throw new UnauthorizedException('Keycloak user creation failed');
      }

      return userId;
    });
  }

  async changePassword({
    userId,
    username,
    oldPassword,
    newPassword,
  }: updatePasswortDTO): Promise<void> {
    // 1) Old password validieren via Token-Endpoint (ROPC)
    await this.authService.login({ username, password: oldPassword });

    // 2) Neues Passwort via Admin REST setzen
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(userId)}/reset-password`, {
      data: { type: 'password', value: newPassword, temporary: false },
      headers: await this.adminJsonHeaders(),
    });
  }

  async sendPasswordResetNotification(id: string): Promise<void> {
    throw new Error(`Method not implemented.${id}`);
  }

  /**
   * Realm-Rolle von User entfernen.
   */
  async removeRealmRoleFromUser(userId: string, roleName: RealmRole | string): Promise<void> {
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

    const randomSuffix = Math.floor(1000 + Math.random() * 9000).toString();
    const baseUsername = `${base}${randomSuffix}`;

    let username = baseUsername;
    let email = input.email ?? `${username}@omnixys.com`;

    // Max fallback attempts
    for (let i = 0; i < 10; i++) {
      const usernameTaken = await this.userExistsByUsername(username);
      const emailTaken = await this.userExistsByEmail(email);

      if (!usernameTaken && !emailTaken) {
        const password = Math.random().toString(36).slice(-8);
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

    throw new Error(
      `Could not generate unique username/email for ${input.firstName} ${input.lastName} after 10 attempts.`,
    );
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
    return this.withSpan('authentication.userUpdate', async (span) => {
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

      const sc = span.spanContext();
      void this.kafka.updateUser(
        { id, firstName: patch.firstName, lastName: patch.lastName, email: patch.email },
        'authentication.userSignUp',
        { traceId: sc.traceId, spanId: sc.spanId },
      );
    });
  }
}
