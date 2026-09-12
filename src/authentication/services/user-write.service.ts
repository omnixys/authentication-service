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
import { keycloakTenantAttributes, resolveTenantId } from '../utils/tenant-context.js';
import { AdminWriteService } from './admin-write.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { AuthenticateReadService } from './read.service.js';
import { ResetService } from './reset.service.js';
import { TenantMembershipClient } from './tenant-membership.client.js';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { DelayedJobKeys, DelayedJobService, ValkeyKey, ValkeyService } from '@omnixys/cache-ts';
import { ContextAccessor, type ClientContext } from '@omnixys/context-ts';
import { guestAuthKeySchema, guestSignUpTokenPayloadSchema } from '@omnixys/contracts-ts';
import { RealmRoleType } from '@omnixys/contracts-ts';
import { EventType, KafkaProducerService, KafkaTopics } from '@omnixys/kafka-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { TraceRunner } from '@omnixys/observability-ts';
import { EncryptionService } from '@omnixys/security-ts';
import { randomBytes, randomInt } from 'node:crypto';

const { SERVICE } = env;

/**
 * Upper bound the sign-up waits for the seat → ticket → link chain completion
 * marker before failing closed and rolling the created guests back.
 */
const GUEST_SIGNUP_PROVISION_TIMEOUT_MS = env.GUEST_SIGNUP_PROVISION_TIMEOUT_MS;

/**
 * Marker key the Invitation service writes once an invitation is linked to a
 * guest. Value is intentionally not sensitive (handshake only).
 */
function guestSignupMarkerKey(invitationId: string, userId: string): string {
  return `guest-signup:${invitationId}:${userId}`;
}

export interface SignUpResult {
  userId: string;
  keycloakSub: string;
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
    private readonly tenantMembershipClient: TenantMembershipClient,
  ) {
    super(omnixysLogger, http);
  }

  /**
   * Guest signup flow (deterministic & invitee-based)
   *
   * Strict provisioning invariant: a guest account may only exist when the full
   * chain seat → ticket → invitation-link completed. After the Kafka fan-out we
   * therefore wait for the completion marker the Invitation service writes once
   * the guest profile is linked. If the chain does not complete within the
   * timeout, every guest created in this call is rolled back (Keycloak + local
   * DB + downstream cleanup events) and the mutation fails without consuming the
   * verification token, so no orphaned guest account can ever be left behind.
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

      const createdUsers: SignUpResult[] = [];

      try {
        const input = guestAuthKeySchema.parse(JSON.parse(raw));

        /**
         * 🔥 NEW: invitee-based processing
         */
        const invitees = input.invitees ?? [];

        if (!invitees.length) {
          throw new GuestSignupException('invitees-missing');
        }

        /**
         * 3️⃣ Process ALL invitees (main + plusOnes). Each invitee is only
         * accepted once its seat → ticket → link chain has fully completed.
         */
        for (const invitee of invitees) {
          const user = await this.createGuestUser({
            firstName: invitee.firstName,
            lastName: invitee.lastName,
            email: invitee.email,
            eventEndsAt: input.eventEndsAt,
            tenantId: input.tenantId,
          });

          createdUsers.push(user);

          await this.publishGuestSignupFanOut(user, invitee.invitationId, signUpToken, input.tenantId);

          const provisioned = await this.awaitGuestProvisioning(
            invitee.invitationId,
            user.userId,
          );

          if (!provisioned) {
            this.logger.warn(
              'Guest provisioning did not complete: invitationId=%s userId=%s',
              invitee.invitationId,
              user.userId,
            );
            throw new GuestSignupException('provisioning-incomplete');
          }
        }

        /**
         * 4️⃣ Delete token → prevents replay
         */
        await this.cacheService.delete(ValkeyKey.guestVerificationAuth, authKey);

        return { users: createdUsers };
      } catch (e: unknown) {
        this.logger.error('Guest sign-up failed: %o', { error: e });

        await this.compensateGuestUsers(createdUsers);

        if (e instanceof GuestSignupException) {
          throw e;
        }
        throw new GuestSignupException('invalid-or-incomplete-state', e);
      }
    });
  }

  /**
   * Publishes the deterministic guest provisioning fan-out for one invitee.
   */
  private async publishGuestSignupFanOut(
    user: SignUpResult,
    invitationId: string,
    signUpToken: string,
    tenantId: string,
  ): Promise<void> {
    await Promise.all([
      this.kafkaProducer.send({
        topic: KafkaTopics.user.createGuest,
        payload: {
          userId: user.userId,
          keycloakSub: user.keycloakSub,
          invitationId,
          token: signUpToken,
          username: user.username,
          email: user.email,
        },
        meta: this.meta(user.userId, 'create guest user', tenantId),
      }),

      this.kafkaProducer.send({
        topic: KafkaTopics.event.addRole,
        payload: {
          userId: user.userId,
          keycloakSub: user.keycloakSub,
          invitationId,
          token: signUpToken,
        },
        meta: this.meta(user.userId, 'assign role', tenantId),
      }),

      this.kafkaProducer.send({
        topic: KafkaTopics.seat.addGuestId,
        payload: {
          userId: user.userId,
          keycloakSub: user.keycloakSub,
          invitationId,
          token: signUpToken,
        },
        meta: this.meta(user.userId, 'assign seat', tenantId),
      }),
    ]);
  }

  /**
   * Waits until the invitation link completion marker is present, i.e. the
   * invitee's seat → ticket → link chain has run end-to-end. Because a ticket
   * requires a seat and the invitation is linked only after ticket creation,
   * the marker proves seat AND ticket exist for the guest.
   */
  private async awaitGuestProvisioning(
    invitationId: string,
    userId: string,
  ): Promise<boolean> {
    const markerKey = guestSignupMarkerKey(invitationId, userId);
    const deadline = Date.now() + GUEST_SIGNUP_PROVISION_TIMEOUT_MS;
    let delayMs = 200;

    for (;;) {
      const marker = await this.cacheService.rawGet(markerKey);
      if (marker) {
        return true;
      }
      if (Date.now() >= deadline) {
        return false;
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      delayMs = Math.min(500, Math.round(delayMs * 1.6));
    }
  }

  /**
   * Rolls back every guest created during a failed sign-up: Keycloak user,
   * local auth record and the downstream cleanup fan-out (seat claims,
   * invitation links, tickets, event access and user profile). Best-effort per
   * user so one failure never blocks the cleanup of the remaining guests.
   */
  private async compensateGuestUsers(users: SignUpResult[]): Promise<void> {
    for (const user of users) {
      try {
        await this.kcRequest('delete', `${paths.users}/${encodeURIComponent(user.keycloakSub)}`);

        await this.prisma.authUser.deleteMany({ where: { id: user.userId } });

        await Promise.all([
          this.kafkaProducer.send({
            topic: KafkaTopics.user.deleteUser,
            payload: { userId: user.userId },
            meta: this.meta(user.userId, 'compensate guest user'),
          }),
          this.kafkaProducer.send({
            topic: KafkaTopics.event.delete,
            payload: { userId: user.userId },
            meta: this.meta(user.userId, 'compensate guest events'),
          }),
          this.kafkaProducer.send({
            topic: KafkaTopics.seat.removeGuestId,
            payload: { userId: user.userId },
            meta: this.meta(user.userId, 'compensate guest seats'),
          }),
          this.kafkaProducer.send({
            topic: KafkaTopics.invitation.deleteUserInvitations,
            payload: { userId: user.userId },
            meta: this.meta(user.userId, 'compensate guest invitations'),
          }),
          this.kafkaProducer.send({
            topic: KafkaTopics.ticket.deleteUserTickets,
            payload: { userId: user.userId },
            meta: this.meta(user.userId, 'compensate guest tickets'),
          }),
        ]);

        this.logger.info('Guest sign-up compensated: userId=%s', user.userId);
      } catch (error) {
        this.logger.error(
          'Guest compensation failed: userId=%s error=%o',
          user.userId,
          error,
        );
      }
    }
  }

  /**
   * Creates a single user in Keycloak + DB
   */
  async createGuestUser(data: {
    firstName: string;
    lastName: string;
    email?: string;
    eventEndsAt: Date;
    tenantId: string;
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
        attributes: keycloakTenantAttributes(data.tenantId),
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
     * Resolve Keycloak subject (K)
     */
    const keycloakSub = await this.findUserIdByUsername(username);
    if (!keycloakSub) {
      throw new AuthenticationUserNotFoundException(username);
    }

    /**
     * Assign role
     */
    await this.adminService.assignRealmRoleToUser(keycloakSub, RealmRoleType.GUEST);

    /**
     * Persist locally: AuthUser.id = U (PostgreSQL uuidv7()), keycloakSub = K
     */
    const createdAuthUser = await this.prisma.authUser.create({
      data: {
        keycloakSub,
        email: finalEmail,
        username,
        mfaPreference: MfaPreference.SECURITY_QUESTIONS,
      },
    });

    await this.tenantMembershipClient.provisionMember(data.tenantId, createdAuthUser.id, 'GUEST');

    await this.adminService.setOmnixysUidAttribute(keycloakSub, createdAuthUser.id);

    const delayMs = Math.max(0, data.eventEndsAt.getTime() - Date.now());

    await this.delayedJobService.schedule({
      type: DelayedJobKeys.user.delete,
      payload: { userId: createdAuthUser.id },
      delayMs,
    });

    return {
      userId: createdAuthUser.id,
      keycloakSub,
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
        ...keycloakTenantAttributes(),
      },
    };

    await this.kcRequest('post', paths.users, {
      data: body,
      headers: await this.adminJsonHeaders(),
    });

    // id ermitteln
    const keycloakSub = await this.findUserIdByUsername(
      data.name ?? `${data.provider}_${data.providerId}`,
    );
    if (!keycloakSub) {
      throw new AuthenticationUserNotFoundException(body.username);
    }

    // Rolle zuweisen
    await this.adminService.assignRealmRoleToUser(keycloakSub, RealmRoleType.USER);

    return keycloakSub;
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
      ...(kcUser.attributes ? { attributes: kcUser.attributes } : {}),
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
    explicitTenantId?: string,
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
      tenantId: resolveTenantId(explicitTenantId),
      service: SERVICE,
      operation,
      version: '1',
      type,
    };
  }
}
