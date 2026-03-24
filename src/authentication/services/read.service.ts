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

import { keycloakConfig, paths } from '../../config/keycloak.js';
import type { KeycloakTokenPayload } from '../models/dtos/kc-token.dto.js';
import type { KeycloakUser } from '../models/dtos/kc-user.dto.js';
import type { KcUser } from '../models/entitys/user.entity.js';
import { toUser, toUsers } from '../models/mappers/user.mapper.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { OmnixysLogger } from '@omnixys/logger';
import * as jose from 'jose';

/**
 * @file Read-Only Zugriff auf Keycloak (Admin-API & Token-Lesen).
 *  - Nutzerlisten, Nutzer by Id
 *  - UserInfo aus Access-Token (JWT Verify)
 */
@Injectable()
export class AuthenticateReadService extends AuthenticateBaseService {
  constructor(logger: OmnixysLogger, http: HttpService) {
    super(logger, http);
  }

  createKeycloakConnectOptions(): typeof keycloakConfig {
    return keycloakConfig;
  }

  /**
   * Liste aller Realm-Benutzer.
   */
  async findAllUsers(): Promise<KcUser[]> {
    void this.logger.debug('finde alle User');
    const raw = await this.kcRequest<KeycloakUser[]>('get', paths.users);
    const users = toUsers(raw);
    return users;
  }

  /**
   * Benutzer per ID (exakt).
   */
  async findById(id: string): Promise<KcUser> {
    void this.logger.debug('findById: id=%s', id);
    const rawData = await this.kcRequest<KeycloakUser>(
      'get',
      `${paths.users}/${encodeURIComponent(id)}`,
      {
        params: { id, exact: true },
      },
    );

    if (rawData?.id !== id) {
      void this.logger.debug('findById: raw=%o', rawData);
      throw new NotFoundException(`User '${id}' nicht gefunden.`);
    }

    void this.logger.debug('findById: raw=%o', rawData);
    const user = toUser(rawData);
    void this.logger.debug('findById: user=%o', user);
    return user;
  }

  async findByUsername(username: string): Promise<KcUser> {
    this.logger.debug('findByUsername: username=%s', username);

    const rawList = await this.kcRequest<KeycloakUser[]>('get', paths.users, {
      params: { username, exact: true },
    });

    if (!Array.isArray(rawList) || rawList.length === 0) {
      this.logger.debug('findByUsername: no result for %s', username);
      throw new NotFoundException(`User '${username}' nicht gefunden.`);
    }

    const raw = rawList[0];
    // this.logger.debug('findByUsername: raw=%o', raw);

    if (raw?.username !== username) {
      throw new NotFoundException(`User '${username}' nicht gefunden.`);
    }

    const user = toUser(raw);
    this.logger.debug('findByUsername: user=%o', user);
    return user;
  }

  /**
   * Benutzerinfo aus verifiziertem JWT.
   */
  async getUserInfo(accessToken: string): Promise<KcUser> {
    const decoded = jose.decodeJwt(accessToken);
    const iss = decoded.iss;
    if (!iss) {
      throw new UnauthorizedException('Missing issuer');
    }
    const payload = await this.verifyJwt<KeycloakTokenPayload>(accessToken, iss);
    return toUser(payload);
  }
}
