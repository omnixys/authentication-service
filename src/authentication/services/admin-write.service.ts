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
import { MfaPreference } from '../../prisma/generated/enums.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { AuthenticationUserNotFoundException } from '../errors/authentication.error.js';
import { AuthenticationInternalException } from '../errors/authentication.error.js';
import { KeycloakUserPatch } from '../models/dtos/kc-user.dto.js';
import type { AdminSignUpInput } from '../models/inputs/sign-up.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { keycloakTenantAttributes } from '../utils/tenant-context.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { OMNIXYS_UID_KEYCLOAK_ATTRIBUTE, RealmRoleType } from '@omnixys/contracts-ts';
import { KafkaProducerService, KafkaTopics, type KafkaMetaInfo } from '@omnixys/kafka-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';

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
    this.logger.debug('Admin sign-up started: %o', { username });

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
      attributes: keycloakTenantAttributes(),
    };

    await this.kcRequest('post', paths.users, {
      data: body,
      headers: await this.adminJsonHeaders(),
    });
    // id ermitteln
    const keycloakSub = await this.findUserIdByUsername(username);
    if (!keycloakSub) {
      throw new AuthenticationUserNotFoundException(username);
    }

    // Rolle zuweisen
    await this.assignRealmRoleToUser(keycloakSub, RealmRoleType.ADMIN);

    const authUser = await this.prisma.authUser.create({
      data: {
        keycloakSub,
        email,
        username,
        mfaPreference: MfaPreference.SECURITY_QUESTIONS,
      },
    });

    await this.setOmnixysUidAttribute(keycloakSub, authUser.id);

    const token = await this.authService.passwordLogin({ username, password });
    return token;
  }

  /**
   * Benutzer vollständig löschen (U und Keycloak):
   *  - Keycloak-User (K) wird über dessen `keycloakSub` gelöscht (nicht über U!),
   *  - AuthUser (U) inkl. aller abhängigen Datensätze via Cascade,
   *  - Kafka-Fan-Out (User, Address, Event, Seat, Invitation, Ticket) mit `userId = U`.
   *
   * `id` darf die interne Omnixys-User-ID (U) oder der Keycloak-Subject (K) sein –
   * beides wird aufgelöst. Idempotent: existiert der AuthUser nicht mehr, ist der
   * Aufruf ein No-op (wichtig für Delayed-Jobs / Duplicate-Events).
   */
  async deleteUser(id: string, actorId: string): Promise<void> {
    const authUser = await this.resolveAuthUser(id);

    if (!authUser) {
      this.logger.warn('User deletion skipped: authUser not found: id=%s', id);
      return;
    }

    const userId = authUser.id;

    // 1) Keycloak: externer User (K) über dessen Subject löschen.
    //    404 → bereits gelöscht → als Erfolg behandeln.
    await this.kcRequest(
      'delete',
      `${paths.users}/${encodeURIComponent(authUser.keycloakSub)}`,
      {},
      { ignoreNotFound: true },
    );

    // 2) Lokale AuthUser (U) inkl. MFA/Credentials via Cascade.
    await this.prisma.authUser.deleteMany({ where: { id: userId } });

    const metadata = (operation: string): KafkaMetaInfo => ({
      operation,
      service: 'authentication-service',
      version: '1',
      type: 'EVENT' as const,
      actorId,
      tenantId: 'omnixys',
    });

    // 3) Fan-Out überall mit der internen User-ID (U).
    await Promise.all([
      this.kafka.send({
        topic: KafkaTopics.user.deleteUser,
        payload: { userId },
        meta: metadata('delete user profile'),
      }),
      this.kafka.send({
        topic: KafkaTopics.address.deleteUserAddresses,
        payload: { userId },
        meta: metadata('delete user addresses'),
      }),
      this.kafka.send({
        topic: KafkaTopics.event.delete,
        payload: { userId },
        meta: metadata('delete user events'),
      }),
      this.kafka.send({
        topic: KafkaTopics.seat.removeGuestId,
        payload: { userId },
        meta: metadata('remove user seat assignments'),
      }),
      this.kafka.send({
        topic: KafkaTopics.invitation.deleteUserInvitations,
        payload: { userId },
        meta: metadata('delete user invitations'),
      }),
      this.kafka.send({
        topic: KafkaTopics.ticket.deleteUserTickets,
        payload: { userId },
        meta: metadata('delete user tickets'),
      }),
    ]);

    this.logger.info('User deletion propagated: %o', { userId });
  }

  /**
   * Löst eine übergebene ID auf: zuerst interne User-ID (U), sonst Keycloak-Subject (K).
   */
  private async resolveAuthUser(id: string): Promise<{
    id: string;
    keycloakSub: string;
  } | null> {
    const byId = await this.prisma.authUser.findUnique({
      where: { id },
      select: { id: true, keycloakSub: true },
    });
    if (byId) {
      return byId;
    }
    const bySub = await this.prisma.authUser.findUnique({
      where: { keycloakSub: id },
      select: { id: true, keycloakSub: true },
    });
    return bySub ?? null;
  }

  /**
   * Prüft, ob der User (U) die Realm-Rolle GUEST besitzt. Robust bei bereits gelöschtem
   * Keycloak-Nutzer: existiert der Keycloak-User nicht mehr (404), wird `true` geliefert,
   * damit der idempotente Aufräum-Flow fortgesetzt wird.
   */
  async isGuest(userId: string): Promise<boolean> {
    const authUser = await this.prisma.authUser.findUnique({
      where: { id: userId },
      select: { keycloakSub: true },
    });
    if (!authUser) {
      return false;
    }

    const roles = await this.kcRequest<Array<{ name?: string }>>(
      'get',
      `${paths.users}/${encodeURIComponent(authUser.keycloakSub)}/role-mappings/realm`,
      {},
      { ignoreNotFound: true },
    );

    if (!roles) {
      return true;
    }

    return roles.some((role) => role.name === this.mapRoleInput(RealmRoleType.GUEST));
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
   * Projects the internal Omnixys user id (U) onto the Keycloak user as the
   * `omnixys_uid` user attribute. This is a projection for token issuance only;
   * AuthUser.id is the source of truth. Keycloak never generates U itself.
   *
   * **Ordering contract (Phase 4 Teil 0):** must run AFTER AuthUser/U has been
   * created and BEFORE any access/ID token for that user is issued, so every
   * freshly issued token carries `sub = K` and `omnixys_user_id = U`.
   *
   * Idempotent: re-running with the same `uid` is a no-op merge; existing
   * attributes are preserved (Keycloak PUT replaces the whole attribute map).
   */
  async setOmnixysUidAttribute(keycloakUserId: string, uid: string): Promise<void> {
    const kcUser = await this.readService.findById(keycloakUserId);
    this.logger.debug('omnixys_uid projection: fetched user attributes: %o', kcUser.attributes);
    const mergedAttributes: Record<string, string[]> = {
      ...(kcUser.attributes ?? {}),
      [OMNIXYS_UID_KEYCLOAK_ATTRIBUTE]: [uid],
    };

    const patch: KeycloakUserPatch = {
      username: kcUser.username,
      firstName: kcUser.firstName,
      lastName: kcUser.lastName,
      email: kcUser.email,
      attributes: mergedAttributes,
    };

    try {
      this.logger.debug('omnixys_uid projection: PUT body: %o', patch);
      await this.kcRequest('put', `${paths.users}/${encodeURIComponent(keycloakUserId)}`, {
        data: patch,
        headers: await this.adminJsonHeaders(),
      });
      this.logger.info('omnixys_uid attribute projected to Keycloak: %o', {
        keycloakUserId,
      });
    } catch (error) {
      this.logger.error('omnixys_uid attribute projection failed: %o', error);
      throw new AuthenticationInternalException('omnixys-uid-projection', error);
    }
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
