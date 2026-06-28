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
import { PrismaService } from '../../prisma/prisma.service.js';
import { AuthenticationUserNotFoundException } from '../errors/authentication.error.js';
import { KeycloakUserPatch } from '../models/dtos/kc-user.dto.js';
import type { AdminSignUpInput } from '../models/inputs/sign-up.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { KafkaProducerService, KafkaTopics, type KafkaMetaInfo } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
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
    logger: OmnixysLogger,
    private authService: AuthWriteService,
    private readonly readService: AuthenticateReadService,
    http: HttpService,
    readonly kafka: KafkaProducerService,
    readonly prisma: PrismaService,
  ) {
    super(logger, http);
  }

  async adminSignUp(input: AdminSignUpInput): Promise<TokenPayload> {
    const { firstName, lastName, email, username, password } = input;
    this.logger.debug('Admin sign-up started', { username });

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
      throw new AuthenticationUserNotFoundException(username);
    }

    // Rolle zuweisen
    await this.assignRealmRoleToUser(userId, RealmRoleType.ADMIN);

    const token = await this.authService.passwordLogin({ username, password });
    return token;
  }

  /**
   * Benutzer löschen.
   */
  async deleteUser(id: string, actorId: string): Promise<void> {
    await this.kcRequest('delete', `${paths.users}/${encodeURIComponent(id)}`);

    await this.prisma.authUser.deleteMany({ where: { id } });

    const metadata = (operation: string): KafkaMetaInfo => ({
      operation,
      service: 'authentication-service',
      version: '1',
      type: 'EVENT' as const,
      actorId,
      tenantId: 'omnixys',
    });

    await Promise.all([
      this.kafka.send({
        topic: KafkaTopics.user.deleteUser,
        payload: { userId: id },
        meta: metadata('delete user profile'),
      }),
      this.kafka.send({
        topic: KafkaTopics.address.deleteUserAddresses,
        payload: { userId: id },
        meta: metadata('delete user addresses'),
      }),
      this.kafka.send({
        topic: KafkaTopics.event.delete,
        payload: { userId: id },
        meta: metadata('delete user events'),
      }),
      this.kafka.send({
        topic: KafkaTopics.seat.removeGuestId,
        payload: { userId: id },
        meta: metadata('remove user seat assignments'),
      }),
      this.kafka.send({
        topic: KafkaTopics.invitation.deleteUserInvitations,
        payload: { userId: id },
        meta: metadata('delete user invitations'),
      }),
      this.kafka.send({
        topic: KafkaTopics.ticket.deleteUserTickets,
        payload: { userId: id },
        meta: metadata('delete user tickets'),
      }),
    ]);

    this.logger.info('User deletion propagated', { userId: id });
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
