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
import { authClientConfig, keycloakConfig, paths } from '../../config/keycloak.js';
import {
  AuthenticationInputException,
  AuthenticationPasswordPolicyException,
  AuthenticationStateException,
  AuthenticationUnauthorizedException,
  AuthenticationUserAlreadyExistsException,
  IdentityProviderAdminCredentialsException,
  IdentityProviderAdminForbiddenException,
  IdentityProviderClientConfigurationException,
  IdentityProviderException,
  IdentityProviderRateLimitedException,
  IdentityProviderRequestRejectedException,
  IdentityProviderResponseException,
} from '../errors/authentication.error.js';
import type { HttpService } from '@nestjs/axios';
import {
  ENUM_TO_KC,
  FrameworkException,
  type RealmRoleType,
  type RoleData,
} from '@omnixys/contracts-ts';
import type { OmnixysLogger } from '@omnixys/logger-ts';
import { TraceRunner } from '@omnixys/observability-ts';
import { InvalidCredentialsException } from '@omnixys/security-ts';
import * as jose from 'jose';
import { firstValueFrom } from 'rxjs';

export type RemoteJwkSet = ReturnType<typeof jose.createRemoteJWKSet>;

const { KC_ADMIN_PASSWORD, KC_ADMIN_USERNAME, KC_CLIENT_SECRET, KC_CLIENT_ID } = env;
const NETWORK_ERROR_CODES = new Set([
  'ECONNABORTED',
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EPIPE',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
]);

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

  /**
   * Basic authentication headers for the dedicated impersonation client
   * (authClientConfig), used only for passwordless session token exchange.
   */
  protected get authClientLoginHeaders(): Record<string, string> {
    const { clientId, clientSecret } = authClientConfig;
    const authorization = Buffer.from(`${clientId}:${clientSecret}`, 'utf8').toString('base64');
    return {
      Authorization: `Basic ${authorization}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    };
  }

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

    this.logger = omnixysLogger.log(this.constructor.name, 'service:authentication');
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
      ignoreNotFound?: boolean;
    } = {
      mapTo: 'throw-on-error',
    },
  ): Promise<T> {
    return TraceRunner.run(`Keycloak Request: ${url}`, async () => {
      const headers: Record<string, string> = { ...cfg.headers };
      const baseURL = keycloakConfig.backchannelUrl;
      const startedAt = Date.now();

      this.logger.info('auth.keycloak.request.start: %o', {
        method: method.toUpperCase(),
        endpoint: url,
      });

      if (cfg.adminAuth !== false) {
        const token = await this.getAdminToken();
        headers.Authorization = `Bearer ${token}`;
      }

      try {
        this.logger.debug('KC request → %s', method.toUpperCase(), {
          hasBody: cfg.data !== undefined,
        });

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
        this.logger.info('auth.keycloak.request.success: %o', {
          method: method.toUpperCase(),
          endpoint: url,
          status: res.status,
          durationMs: Date.now() - startedAt,
        });
        return res.data;
      } catch (err: unknown) {
        const info = this.keycloakErrorInfo(err);
        const { status, responseData, oauthError, safeMessage } = info;

        this.logger.warn('auth.keycloak.request.failure: %o', {
          method: method.toUpperCase(),
          endpoint: url,
          status,
          oauthError,
          networkCode: info.networkCode,
          durationMs: Date.now() - startedAt,
        });

        this.logger.warn(
          'Keycloak request rejected method=%s path=%s status=%s oauthError=%s',
          method.toUpperCase(),
          url,
          status,
          oauthError,
        );

        if (
          behavior.mapTo === 'null-on-401' &&
          (oauthError === 'invalid_grant' || (!oauthError && (status === 400 || status === 401)))
        ) {
          return null as T;
        }

        if (status === 404) {
          if (behavior.ignoreNotFound) {
            this.logger.warn(
              'KC 404 on %s %s → treated as idempotent not-found no-op: %o',
              method.toUpperCase(),
              url,
              safeMessage,
            );
            return null as T;
          }
          throw new AuthenticationStateException('identity-resource-not-found', err);
        }
        if (status === 409 && behavior.returnNullOn409) {
          this.logger.warn(
            'KC 409 Conflict on %s %s → returning null for fallback logic: %o',
            method.toUpperCase(),
            url,
            safeMessage,
          );
          return null as T;
        }

        if (status === 409) {
          throw new AuthenticationUserAlreadyExistsException(
            'username',
            this.extractConflictField(responseData),
          );
        }

        if (status === 400) {
          if (this.isPasswordPolicyError(responseData)) {
            throw new AuthenticationPasswordPolicyException(safeMessage);
          }
          if (!oauthError) {
            throw new AuthenticationInputException('identity-provider-input-invalid');
          }
        }
        throw this.mapKeycloakError(
          err,
          info,
          `${method.toUpperCase()} ${url}`,
          cfg.adminAuth !== false,
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
  protected async verifyJwt<T extends object>(
    token: string,
    issuer: string,
    jwksUri?: string,
  ): Promise<T> {
    const JWKS = this.getJwks(issuer, jwksUri);
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
    if (!KC_CLIENT_ID || !KC_CLIENT_SECRET) {
      throw new IdentityProviderClientConfigurationException('acquire-admin-token');
    }
    if (!KC_ADMIN_USERNAME || !KC_ADMIN_PASSWORD) {
      throw new IdentityProviderAdminCredentialsException('acquire-admin-token');
    }

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

    const startedAt = Date.now();
    try {
      this.logger.info('auth.keycloak.admin-token.start: %o', {
        phase: 'keycloak.admin-token',
        endpoint: '/realms/omnixys/protocol/openid-connect/token',
      });
      const res = await firstValueFrom(
        this.http.post<{ access_token: string; expires_in: number }>(
          `/realms/omnixys/protocol/openid-connect/token`,
          params.toString(),
          {
            baseURL: keycloakConfig.backchannelUrl,
            headers: this.loginHeaders,
          },
        ),
      );

      const token = res.data?.access_token;
      const expiresIn = Number(res.data.expires_in ?? 60);
      if (
        typeof token !== 'string' ||
        token.length === 0 ||
        !Number.isFinite(expiresIn) ||
        expiresIn <= 0
      ) {
        throw new IdentityProviderResponseException('acquire-admin-token', res.status);
      }
      this.#adminToken = {
        token,
        expiresAt: Date.now() + Math.max(1, expiresIn - 30) * 1000,
      };
      this.logger.info('admin_token_acquired: %o', { expiresIn });
      this.logger.info('auth.keycloak.admin-token.success: %o', {
        phase: 'keycloak.admin-token',
        endpoint: '/realms/omnixys/protocol/openid-connect/token',
        status: res.status,
        durationMs: Date.now() - startedAt,
      });
      return token;
    } catch (error: unknown) {
      const infoForLog = this.keycloakErrorInfo(error);
      this.logger.warn('auth.keycloak.admin-token.failure: %o', {
        phase: 'keycloak.admin-token',
        endpoint: '/realms/omnixys/protocol/openid-connect/token',
        status: infoForLog.status,
        oauthError: infoForLog.oauthError,
        networkCode: infoForLog.networkCode,
        durationMs: Date.now() - startedAt,
      });
      if (error instanceof FrameworkException) {
        throw error;
      }
      const info = this.keycloakErrorInfo(error);
      throw this.mapKeycloakError(error, info, 'acquire-admin-token', true, true);
    }
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
      this.logger.warn('Realm role lookup failed: %o', { role: effective, error: err });
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

  private mapKeycloakError(
    error: unknown,
    info: KeycloakErrorInfo,
    operation: string,
    adminAuth: boolean,
    adminTokenRequest = false,
  ): Error {
    const { status, oauthError } = info;

    if (info.networkCode && NETWORK_ERROR_CODES.has(info.networkCode)) {
      return new IdentityProviderException('keycloak', operation, status, error);
    }

    if (oauthError === 'invalid_client') {
      return new IdentityProviderClientConfigurationException(operation, status, error);
    }
    if (oauthError === 'invalid_grant') {
      return adminTokenRequest
        ? new IdentityProviderAdminCredentialsException(operation, status, error)
        : new InvalidCredentialsException();
    }
    if (status === 401) {
      return adminAuth
        ? new IdentityProviderAdminCredentialsException(operation, status, error)
        : new InvalidCredentialsException();
    }
    if (status === 403) {
      return adminAuth
        ? new IdentityProviderAdminForbiddenException(operation, status, error)
        : new AuthenticationUnauthorizedException(operation);
    }
    if (status === 429) {
      return new IdentityProviderRateLimitedException(operation, status, error);
    }
    if (status === undefined || status >= 500) {
      return new IdentityProviderException('keycloak', operation, status, error);
    }
    return new IdentityProviderRequestRejectedException(operation, status, oauthError, error);
  }

  private keycloakErrorInfo(error: unknown): KeycloakErrorInfo {
    const candidate =
      error && typeof error === 'object'
        ? (error as {
            code?: unknown;
            message?: unknown;
            response?: { status?: unknown; data?: unknown };
          })
        : undefined;
    const rawStatus = candidate?.response?.status;
    const status = typeof rawStatus === 'number' ? rawStatus : undefined;
    const responseData = candidate?.response?.data;
    const body =
      responseData && typeof responseData === 'object'
        ? (responseData as Record<string, unknown>)
        : undefined;
    const oauthError = typeof body?.error === 'string' ? body.error.toLowerCase() : undefined;
    const rawMessage =
      typeof body?.errorMessage === 'string'
        ? body.errorMessage
        : typeof body?.error_description === 'string'
          ? body.error_description
          : typeof candidate?.message === 'string'
            ? candidate.message
            : 'Identity provider request failed';

    return {
      status,
      responseData,
      oauthError,
      networkCode: typeof candidate?.code === 'string' ? candidate.code : undefined,
      safeMessage: rawMessage.slice(0, 500),
    };
  }

  /**
   * Retrieves or caches a remote JWKS instance for a given issuer.
   *
   * @param issuer - The issuer URL.
   * @returns The JWKS retrieval function.
   */
  private getJwks(issuer: string, jwksUri?: string): RemoteJwkSet {
    const url = new URL(jwksUri ?? `${issuer}/protocol/openid-connect/certs`);
    const key = url.href;
    let jwks = this.#jwksCache.get(key);
    if (!jwks) {
      jwks = jose.createRemoteJWKSet(url);
      this.#jwksCache.set(key, jwks);
    }
    return jwks;
  }
}

interface KeycloakErrorInfo {
  readonly status?: number;
  readonly responseData?: unknown;
  readonly oauthError?: string;
  readonly networkCode?: string;
  readonly safeMessage: string;
}
