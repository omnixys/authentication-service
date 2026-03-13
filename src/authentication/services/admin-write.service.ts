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
import { PrismaService } from '../../prisma/prisma.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { KeycloakUserPatch } from '../models/dtos/kc-user.dto.js';
import type { AdminSignUpInput } from '../models/inputs/sign-up.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException } from '@nestjs/common';
import { RealmRoleType } from '@omnixys/contracts';

/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class AdminWriteService extends AuthenticateBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    private authService: AuthWriteService,
    private readonly readService: AuthenticateReadService,
    http: HttpService,
    private readonly kafka: KafkaProducerService,
    private readonly prisma: PrismaService,
  ) {
    super(logger, trace, http);
  }

  async adminSignUp(input: AdminSignUpInput): Promise<TokenPayload> {
    return this.withSpan('authentication.signUp', async (_span) => {
      const { firstName, lastName, email, username, password } = input;
      void this.logger.debug('signUp: input=%o', input);

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
        emailVerified: true,
        requiredActions: [],
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
      await this.assignRealmRoleToUser(userId, RealmRoleType.ADMIN);

      const token = await this.authService.login({ username, password });
      return token;
    });
  }

  /**
   * Benutzer löschen.
   */
  async deleteUser(id: string): Promise<void> {
    return this.withSpan('authentication.signUp', async (span) => {
      await this.kcRequest('delete', `${paths.users}/${encodeURIComponent(id)}`);

      await this.prisma.authUser.delete({ where: { id } });

      const sc = span.spanContext();

      void this.kafka.deleteUser({ id }, 'authentication.deleteUser', {
        traceId: sc.traceId,
        spanId: sc.spanId,
      });

      void this.kafka.deleteAddresses({ id }, 'authentication.deleteUser', {
        traceId: sc.traceId,
        spanId: sc.spanId,
      });
    });
  }

  /**
   * Passwort setzen (nicht temporär).
   */
  async setUserPassword(id: string, newPassword: string): Promise<void> {
    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(id)}/reset-password`, {
      data: { type: 'password', value: newPassword, temporary: false },
      headers: await this.adminJsonHeaders(),
    });
  }

  async updateUser(id: string, input: UpdateMyProfileInput): Promise<void> {
    // 1) Bestehenden User laden (für Merge)
    const kcUser = await this.readService.findById(id);

    // 6) KC-User Patch – nur attributes setzen, wenn wir wirklich was schreiben wollen
    const patch: KeycloakUserPatch = {
      username: input.username ?? kcUser.username,
      firstName: input.firstName ?? kcUser.firstName,
      lastName: input.lastName ?? kcUser.lastName,
      email: input.email ?? kcUser.email,
    };

    await this.kcRequest('put', `${paths.users}/${encodeURIComponent(id)}`, {
      data: patch,
      headers: await this.adminJsonHeaders(),
    });
  }

  /**
   * Realm-Rolle einem User zuweisen.
   */
  async assignRealmRoleToUser(userId: string, roleName: RealmRoleType): Promise<void> {
    const current = await this.getUserRealmRoles(userId);

    if (current.some((r) => r.name === this.mapRoleInput(roleName))) {
      return;
    }
    const role = await this.getRealmRole(roleName);
    await this.kcRequest(
      'post',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
      { data: [role] },
    );

    void this.logger.debug('assignRealmRoleToUser: roleName=%s', roleName);
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
}
