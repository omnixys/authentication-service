// TODO resolve eslint

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

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { KcUser } from '../models/entitys/user.entity.js';
import { toEnumRoles } from '../models/enums/role.enum.js';
import { AuthenticateReadService } from '../services/read.service.js';
import {
  BadRequestException,
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Args, ID, Query, Resolver } from '@nestjs/graphql';
import {
  CookieAuthGuard,
  CurrentUser,
  CurrentUserData,
  HeaderAuthGuard,
  Public,
  RoleGuard,
  Roles,
} from '@omnixys/auth';
import { RealmRole } from '@omnixys/contracts';

/**
 * @file GraphQL-Resolver für **lesende** Authentication-Abfragen (ME/USERS).
 *
 * @remarks
 * - Nutzt den {@link AuthenticateReadService} für sämtliche Leseoperationen.
 * - Liest das Access-Token bevorzugt aus dem HttpOnly-Cookie `kc_access_token`,
 *   alternativ aus dem optionalen Query-Argument `token`.
 * - Öffentliche Endpunkte sind mit `@Public()` gekennzeichnet.
 * - Strikt typisiert, keine Verwendung von `any`.
 *
 * @packageDocumentation
 */

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
/**
 * Stellt Queries rund um Benutzerinformationen bereit:
 * - `users`: Liste aller Realm-User
 * - `me`: Informationen zum aktuellen Benutzer (aus Access-Token)
 * - `getById`: Benutzer per ID
 */
export class AuthQueryResolver {
  private readonly logger = getLogger(AuthQueryResolver.name);

  constructor(private readonly read: AuthenticateReadService) {}

  /**
   * Liste aller Benutzer im Realm.
   *
   * @returns Array von {@link KcUser}
   *
   * @example
   * ```graphql
   * query {
   *   users { id username email }
   * }
   * ```
   */
  @Query(() => [KcUser], { name: 'kc_users' })
  async getUsers(): Promise<KcUser[]> {
    this.logger.debug('Get All Users');
    return this.read.findAllUsers();
  }

  /**
   * Informationsabfrage zum aktuellen Benutzer.
   *
   * @param ctx GraphQL-Kontext (enthält `req/res` zum Auslesen der Cookies)
   * @param token Optionales Access-Token (Fallback, wenn kein Cookie vorhanden ist)
   * @returns {@link User}
   *
   * @example
   * ```graphql
   * query {
   *   me { id username email }
   * }
   * ```
   */
  @Query(() => KcUser, { name: 'meByToken' })
  @UseGuards(HeaderAuthGuard, RoleGuard)
  @Public()
  async meByToken(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<KcUser> {
    this.logger.debug('meByToken() invoked');

    if (!currentUser) {
      this.logger.warn('me() aufgerufen ohne gültigen Benutzer im Kontext');
      throw new BadRequestException(
        'Ungültige Benutzeranfrage – kein User im Kontext',
      );
    }

    this.logger.debug('user=%o', currentUser);

    if (!currentUser?.id) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    const user = await this.read.findById(currentUser.id);
    return { ...user, roles: toEnumRoles(currentUser.roles) };
  }

  @Query(() => KcUser, { name: 'meAuth' })
  @UseGuards(CookieAuthGuard, RoleGuard)
  @Roles(RealmRole.ADMIN, RealmRole.USER)
  async me(@CurrentUser() currentUser: CurrentUserData): Promise<KcUser> {
    this.logger.debug('me By Cookie');

    if (!currentUser) {
      this.logger.warn('me() aufgerufen ohne gültigen Benutzer im Kontext');
      throw new BadRequestException(
        'Ungültige Benutzeranfrage – kein User im Kontext',
      );
    }

    this.logger.debug('user=%o', currentUser);

    if (!currentUser?.id) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    const user = await this.read.findById(currentUser.id);
    return { ...user, roles: toEnumRoles(currentUser.roles) };
  }

  /**
   * Holt einen Benutzer per **ID**.
   *
   * @param id Keycloak-UUID
   * @returns {@link User}
   *
   * @example
   * ```graphql
   * query {
   *   getById(id: "0b9d...") { id username email }
   * }
   * ```
   */
  @Query(() => KcUser, { name: 'getById' })
  async getById(@Args('id', { type: () => ID }) id: string): Promise<KcUser> {
    this.logger.debug('getById: id=%s', id);
    return this.read.findById(id);
  }

  @Query(() => KcUser, { name: 'getByUsername' })
  async getByUsername(
    @Args('username', { type: () => String }) username: string,
  ): Promise<KcUser> {
    this.logger.debug('getByUsername: username=%s', username);
    return this.read.findByUsername(username);
  }
}
