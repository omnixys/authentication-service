/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
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
import { keycloakConfig, paths } from '../../config/keycloak.js';
import {
  AuthenticationInputException,
  AuthenticationPasswordPolicyException,
  AuthenticationStateException,
  AuthenticationUnauthorizedException,
  AuthenticationUserAlreadyExistsException,
  IdentityProviderException,
} from '../errors/authentication.error.js';
import type { HttpService } from '@nestjs/axios';
import type { OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import { InvalidCredentialsException } from '@omnixys/security';
import type { RoleData } from '@omnixys/contracts';
import { ENUM_TO_KC, type RealmRoleType } from '@omnixys/contracts';
import * as jose from 'jose';
import { firstValueFrom } from 'rxjs';

export type RemoteJwkSet = ReturnType<typeof jose.createRemoteJWKSet>;

const { KC_ADMIN_PASSWORD, KC_ADMIN_USERNAME, KC_CLIENT_SECRET, KC_CLIENT_ID } = env;

/**
 * Shared base class for Keycloak read/write services.
 *
 * Provides unified Keycloak request handling with:
 * - Admin authentication and error mapping
 * - Admin token caching with expiration buffer
 * - JWKS caching and JWT verification
 * - OpenTelemetry tracing helpers
 * - Utility methods for role and attribute mapping
 *
 * This class only provides shared infrastructure, not business logic.
 */
export abstract class AuthenticateBaseService {
  /** Basic authentication headers for token/logout requests. */
  protected readonly loginHeaders: Record<string, string>;

  protected readonly logger;

  /** Cached JSON Web Key Sets per issuer. */
  #jwksCache = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

  /** Cached admin token with expiration timestamp (ms). */
  #adminToken?: { token: string; expiresAt: number };

  /**
   * Initializes a new instance of the KeycloakBaseService.
   *
   * @param loggerService - The centralized logger service.
   * @param http - The injected NestJS HttpService.
   */
  protected constructor(
    omnixysLogger: OmnixysLogger,
    protected readonly http: HttpService,
  ) {
    const { clientId, clientSecret } = keycloakConfig;
    const authorization = Buffer.from(`${clientId}:${clientSecret}`, 'utf8').toString('base64');
    this.loginHeaders = {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    this.logger = omnixysLogger.log(this.constructor.name);
  }

  /**
   * Executes a unified Keycloak HTTP request with optional admin authentication.
   *
   * @param method - The HTTP method (get, post, put, delete).
   * @param url - The path relative to the Keycloak base URL.
   * @param cfg - Optional request configuration.
   * @param behavior - Defines how errors should be handled.
   * @returns The parsed response data.
   * @throws {UnauthorizedException | NotFoundException | BadRequestException | Error}
   */
  protected async kcRequest<T = unknown>(
    method: 'get' | 'post' | 'put' | 'delete',
    url: string,
    cfg: {
      params?: Record<string, unknown>;
      data?: unknown;
      headers?: Record<string, string>;
      adminAuth?: boolean;
    } = {},
    behavior: {
      mapTo?: 'null-on-401' | 'throw-on-error';
      returnNullOn409?: boolean;
    } = {
      mapTo: 'throw-on-error',
    },
  ): Promise<T> {
    return TraceRunner.run(`Keycloak Request: ${url}`, async () => {
      const headers: Record<string, string> = { ...cfg.headers };
      const baseURL = keycloakConfig.url;

      if (cfg.adminAuth !== false) {
        const token = await this.getAdminToken();
        headers.Authorization = `Bearer ${token}`;
      }

      try {
        this.logger.debug(
          'KC request → %s %s | body: %o',
          method.toUpperCase(),
          url,
          cfg.data && typeof cfg.data === 'object'
            ? this.sanitizeLogPayload(cfg.data as Record<string, unknown>)
            : cfg.data,
        );

        const res = await firstValueFrom(
          this.http.request<T>({
            method,
            url,
            baseURL,
            params: cfg.params,
            data: cfg.data,
            headers,
          }),
        );
        return res.data;
      } catch (err: any) {
        const rawStatus: unknown = err.response?.status;
        const status = typeof rawStatus === 'number' ? rawStatus : 500;

        const responseData = err.response?.data;
        const errorMessage =
          typeof responseData === 'string'
            ? responseData
            : responseData && typeof responseData === 'object'
              ? ((responseData as Record<string, unknown>).errorMessage ??
                (responseData as Record<string, unknown>).error_description ??
                JSON.stringify(responseData))
              : err.message;

        this.logger.warn(
          'Keycloak %s %s → status=%s body=%s',
          method.toUpperCase(),
          url,
          status,
          errorMessage,
        );

        if (behavior.mapTo === 'null-on-401' && (status === 400 || status === 401)) {
          void this.logger.warn('%s %s -> %s %o', method.toUpperCase(), url, status, responseData);
          return null as T;
        }

        if (status === 401) {
          throw new InvalidCredentialsException('Identity provider rejected credentials');
        }
        if (status === 404) {
          throw new AuthenticationStateException('identity-resource-not-found', err);
        }
        if (status === 409 && behavior.returnNullOn409) {
          this.logger.warn(
            'KC 409 Conflict on %s %s → returning null for fallback logic: %o',
            method.toUpperCase(),
            url,
            errorMessage,
          );
          return null as T;
        }

        if (status === 409) {
          throw new AuthenticationUserAlreadyExistsException(
            'username',
            this.extractConflictField(responseData),
          );
        }

        if (status === 403) {
          throw new AuthenticationUnauthorizedException(`${method.toUpperCase()} ${url}`);
        }

        if (status === 400) {
          this.logger.warn('KC 400 on %s %s — body: %s', method.toUpperCase(), url, errorMessage);
          if (this.isPasswordPolicyError(responseData)) {
            throw new AuthenticationPasswordPolicyException(String(errorMessage));
          }
          throw new AuthenticationInputException(String(errorMessage));
        }

        if (status >= 400 && status < 500) {
          throw new AuthenticationInputException(String(errorMessage));
        }

        throw new IdentityProviderException(
          'keycloak',
          `${method.toUpperCase()} ${url}`,
          status,
          err,
        );
      }
    });
  }

  /**
   * Verifies a JWT using the cached JWKS for the given issuer.
   *
   * @param token - The access token to verify.
   * @param issuer - The expected issuer URL.
   * @returns The decoded JWT payload.
   */
  protected async verifyJwt<T extends object>(token: string, issuer: string): Promise<T> {
    const JWKS = this.getJwks(issuer);
    const { payload } = await jose.jwtVerify(token, JWKS, { issuer });
    return payload as T;
  }

  /**
   * Retrieves and caches an admin access token.
   * Includes a 30-second pre-expiration buffer.
   *
   * @returns The valid admin access token.
   */
  protected async getAdminToken(): Promise<string> {
    const now = Date.now();
    if (this.#adminToken && this.#adminToken.expiresAt > now) {
      return this.#adminToken.token;
    }

    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: KC_CLIENT_ID,
      client_secret: KC_CLIENT_SECRET,
      username: KC_ADMIN_USERNAME,
      password: KC_ADMIN_PASSWORD,
      scope: 'openid',
    });

    const res = await firstValueFrom(
      this.http.post<{ access_token: string; expires_in: number }>(
        `/realms/omnixys/protocol/openid-connect/token`,
        params.toString(),
        {
          baseURL: keycloakConfig.url,
          headers: this.loginHeaders,
        },
      ),
    );

    const token = res.data.access_token;
    const expiresIn = Number(res.data.expires_in ?? 60);
    this.#adminToken = {
      token,
      expiresAt: Date.now() + Math.max(1, expiresIn - 30) * 1000,
    };
    return token;
  }

  /**
   * Builds headers for JSON-based admin requests.
   *
   * @returns Authorization and Content-Type headers.
   */
  protected async adminJsonHeaders(): Promise<Record<string, string>> {
    return {
      Authorization: `Bearer ${await this.getAdminToken()}`,
      'Content-Type': 'application/json',
    };
  }

  /**
   * Loads and validates a realm role by name.
   *
   * @param roleName - The role to load.
   * @returns The corresponding Keycloak role data.
   * @throws {NotFoundException} If the role does not exist.
   */
  protected async getRealmRole(roleName: RealmRoleType | string): Promise<RoleData> {
    const effective = this.mapRoleInput(roleName);

    try {
      const role = await this.kcRequest<RoleData>(
        'get',
        `${paths.roles}/${encodeURIComponent(effective)}`,
      );
      if (!role?.id || !role?.name) {
        throw new AuthenticationStateException('realm-role-incomplete');
      }
      return { id: role.id, name: role.name };
    } catch (err) {
      this.logger.warn('Realm role lookup failed', { role: effective, error: err });
      throw new AuthenticationStateException('realm-role-not-found', err);
    }
  }

  /**
   * Loads all realm roles assigned to a given user.
   *
   * @param userId - The Keycloak user ID.
   * @returns A list of assigned realm roles.
   */
  protected async getUserRealmRoles(userId: string): Promise<RoleData[]> {
    return this.kcRequest<RoleData[]>(
      'get',
      `${paths.users}/${encodeURIComponent(userId)}/role-mappings/realm`,
    );
  }

  /**
   * Resolves a user ID from a given username.
   *
   * @param username - The username to search for.
   * @returns The user ID or null if not found.
   */
  protected async findUserIdByUsername(username: string): Promise<string | null> {
    const data = await this.kcRequest<Array<{ id?: string }>>('get', paths.users, {
      params: { username, exact: true },
    });
    return data?.[0]?.id ?? null;
  }

  /**
   * Maps a role enum or string to its actual Keycloak role name.
   *
   * @param input - The role enum or string.
   * @returns The mapped role name.
   */
  protected mapRoleInput(input: RealmRoleType | string): string {
    const key = String(input).toUpperCase() as RealmRoleType;
    return ENUM_TO_KC[key] ?? String(input);
  }

  /**
   * Strips sensitive fields from a payload object for safe debug logging.
   */
  private sanitizeLogPayload(data: Record<string, unknown>): Record<string, unknown> {
    const safe = { ...data };
    if ('password' in safe) {
      const pwLen = typeof safe.password === 'string' ? safe.password.length : 0;
      safe.password = safe.password ? `[defined len=${pwLen}]` : '[undefined]';
    }
    if ('credentials' in safe && Array.isArray(safe.credentials)) {
      safe.credentials = safe.credentials.map((c: Record<string, unknown>) => ({
        ...c,
        value: c.value ? '[REDACTED]' : '[undefined]',
      }));
    }
    return safe;
  }

  /**
   * Extracts the conflicting field (username/email) from a Keycloak 409 response.
   */
  private extractConflictField(responseData: unknown): 'username' | 'email' {
    if (responseData && typeof responseData === 'object') {
      const body = responseData as Record<string, unknown>;
      const msg =
        typeof body.errorMessage === 'string'
          ? body.errorMessage
          : typeof body.error === 'string'
            ? body.error
            : '';
      if (msg.toLowerCase().includes('email')) {
        return 'email';
      }
      if (msg.toLowerCase().includes('username')) {
        return 'username';
      }
    }
    return 'username';
  }

  /**
   * Checks whether a Keycloak 400 response indicates a password policy violation.
   */
  private isPasswordPolicyError(responseData: unknown): boolean {
    if (responseData && typeof responseData === 'object') {
      const body = responseData as Record<string, unknown>;
      const msg = typeof body.errorMessage === 'string' ? body.errorMessage : '';
      return msg.toLowerCase().includes('password policy');
    }
    return false;
  }

  /**
   * Retrieves or caches a remote JWKS instance for a given issuer.
   *
   * @param issuer - The issuer URL.
   * @returns The JWKS retrieval function.
   */
  private getJwks(issuer: string): RemoteJwkSet {
    const url = new URL(`${issuer}/protocol/openid-connect/certs`);
    const key = url.href;
    let jwks = this.#jwksCache.get(key);
    if (!jwks) {
      jwks = jose.createRemoteJWKSet(url);
      this.#jwksCache.set(key, jwks);
    }
    return jwks;
  }
}
