/* eslint-disable @typescript-eslint/explicit-function-return-type */
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

import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { LogInInput } from '../models/inputs/log-in.input.js';
import { LoginTotpInput } from '../models/inputs/login-totp.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthWriteService } from '../services/authentication-write.service.js';
import { WebAuthnService } from '../services/web-authn.service.js';
import { BadUserInputException } from '../utils/error.util.js';
import {
  BadRequestException,
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Args, Mutation, Resolver } from '@nestjs/graphql';
import { ClientInfo } from '@omnixys/context';
import { LoggingInterceptor, OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import {
  CookieAuthGuard,
  CurrentUser,
  CurrentUserData,
  Public,
} from '@omnixys/security';
import { ClientContext } from '@omnixys/shared';
import { AuthenticationResponseJSON } from '@simplewebauthn/server';

/**
 * GraphQL resolver providing mutation endpoints for user authentication.
 *
 * @public
 */
@Resolver()
@UseInterceptors(LoggingInterceptor)
export class AuthMutationResolver {
  private readonly logger;

  /**
   * Constructs an {@link AuthMutationResolver} instance.
   *
   * @param loggerService - Provides structured logging utilities.
   * @param authService - Handles authentication and token operations.
   * @param adminService - Handles administrative user management.
   */
  constructor(
    private readonly omnixysLogger: OmnixysLogger,
    private readonly authService: AuthWriteService,
    private readonly webAuthnService: WebAuthnService,
  ) {
    this.logger = this.omnixysLogger.log(AuthMutationResolver.name);
  }

  /**
   * Performs a password-based login (ROPC flow).
   *
   * @remarks
   * - Sets `kc_access_token` and `kc_refresh_token` as HttpOnly cookies.
   * - Returns a {@link TokenPayload} object containing both tokens.
   *
   * @param input - User credentials (`username`, `password`).
   * @param ctx - GraphQL context containing HTTP request/response.
   * @returns {@link TokenPayload} containing access and refresh tokens.
   * @throws {@link BadUserInputError} If credentials are invalid.
   */
  @Mutation(() => TokenPayload)
  @Public()
  async credentialsLogin(
    @Args('input', { type: () => LogInInput }) input: LogInInput,
    @ClientInfo() client: ClientContext,
  ): Promise<TokenPayload> {
    return TraceRunner.run('Credentials Login Resolver', async () => {
      // const res = ctx?.reply;
      this.logger.debug('login: input=%o', input);

      const ip = client.ip;
      const userAgent = client.userAgent;
      const acceptLanguage = client.locale;
      const clientDeviceId = client.device;

      return this.authService.passwordLogin({
        ...input,
        ip,
        userAgent,
        acceptLanguage,
        clientDeviceId,
      });
    });
  }

  /**
   * Refreshes authentication tokens using a valid refresh token.
   *
   * @remarks
   * If no explicit token is passed as argument, this method automatically
   * uses the `kc_refresh_token` cookie (if available).
   *
   * @param refreshToken - Optional token string to refresh manually.
   * @param ctx - GraphQL context containing cookies and response.
   * @returns A refreshed {@link TokenPayload}.
   * @throws {@link BadUserInputError} If the refresh token is invalid or expired.
   */
  @Mutation(() => TokenPayload, { name: 'refresh' })
  @UseGuards(CookieAuthGuard)
  async refresh(@CurrentUser() user: CurrentUserData): Promise<TokenPayload> {
    return TraceRunner.run('Refresh Resolver', async () => {
      this.logger.debug(
        '[authentication-mutation.resolver.ts] Refresh %s accessToken...',
        user.username,
      );

      const refreshToken = user.refresh_token;

      const result = await this.authService.refresh(refreshToken);
      if (!result) {
        throw new BadUserInputException('Invalid or expired refresh token.');
      }

      this.logger.info(
        '[authentication-mutation.resolver.ts] Refresh Success!',
      );
      return result;
    });
  }

  /**
   * Logs out a user by invalidating their refresh token
   * and clearing all authentication cookies.
   *
   * @param ctx - GraphQL context containing the HTTP response.
   * @returns {@link SuccessPayload} indicating operation status.
   */
  @UseGuards(CookieAuthGuard)
  @Mutation(() => SuccessPayload, { name: 'logout' })
  async logout(@CurrentUser() user: CurrentUserData): Promise<SuccessPayload> {
    return TraceRunner.run('Logout Resolver', async () => {
      const value = user.refresh_token;
      await this.authService.logout(value);
      return { ok: true, message: 'Successfully logged out.' };
    });
  }

  /* =====================================================
     STEP 1 – Generate Options
  ===================================================== */

  @Mutation(() => JsonScalar)
  async generatePasswordlessOptions(@Args('email') email: string) {
    return TraceRunner.run('generate Passwordless Token Resolver', async () => {
      return this.webAuthnService.generatePasswordlessOptions(email);
    });
  }

  @Mutation(() => JsonScalar)
  async generateWebAuthnAuthOptions() {
    return TraceRunner.run('Generate WebAuthn Token Resolver', async () => {
      return this.webAuthnService.generateDiscoverableAuthOptions();
    });
  }

  /* =====================================================
     STEP 2 – Verify + Create Session
  ===================================================== */

  @Mutation(() => TokenPayload)
  async verifyPasswordlessAuthentication(
    @Args('response', { type: () => JsonScalar }) response: unknown,
    @ClientInfo() client: ClientContext,
  ): Promise<TokenPayload> {
    return TraceRunner.run('Verify Passwordless Auth Resolver', async () => {
      if (!response || typeof response !== 'object') {
        throw new BadRequestException('Invalid WebAuthn response');
      }

      const userId =
        await this.webAuthnService.verifyPasswordlessAuthentication(
          response as AuthenticationResponseJSON,
        );

      if (!userId) {
        throw new UnauthorizedException('Authentication failed');
      }

      const token = await this.authService.createPasswordlessSession(
        userId,
        client,
      );
      return token;
    });
  }

  @Mutation(() => TokenPayload)
  async verifyWebAuthnAuthentication(
    @Args('response', { type: () => JsonScalar }) response: unknown,
    @ClientInfo() client: ClientContext,
  ): Promise<TokenPayload> {
    return TraceRunner.run('Verify WebAuthn Resolver', async () => {
      if (!response || typeof response !== 'object') {
        throw new BadRequestException('Invalid WebAuthn response');
      }

      const userId =
        await this.webAuthnService.verifyDiscoverableAuthentication(
          response as AuthenticationResponseJSON,
        );

      if (!userId) {
        throw new UnauthorizedException('Authentication failed');
      }

      const token = await this.authService.createPasswordlessSession(
        userId,
        client,
      );
      return token;
    });
  }

  @Mutation(() => TokenPayload)
  async loginTotp(
    @Args('input') input: LoginTotpInput,
    @ClientInfo() client: ClientContext,
  ): Promise<TokenPayload> {
    return TraceRunner.run('Login TOTP Resolver', async () => {
      const ip = client.ip;
      const userAgent = client.userAgent;
      const acceptLanguage = client.locale;
      const clientDeviceId = client.device;

      const token = await this.authService.loginWithTotp({
        username: input.username,
        code: input.code,

        ip,
        userAgent,
        acceptLanguage,
        clientDeviceId,
      });
      return token;
    });
  }

  @Mutation(() => Boolean)
  async sendMagicLink(
    @Args('email') email: string,
    @ClientInfo() client: ClientContext,
  ): Promise<boolean> {
    return TraceRunner.run('Send Magic Link Resolver', async () => {
      try {
        void this.authService.requestMagicLink(email, client);
      } catch (error) {
        // Intentionally swallow errors to avoid leaking account existence.
        // Log internally for monitoring & auditing.
        this.logger.warn('Magic Link request failed silently', {
          email,
          ip: client.ip,
          error: error instanceof Error ? error.message : 'unknown',
        });
      }

      return true;
    });
  }

  @Mutation(() => TokenPayload)
  async verifyMagicLink(
    @Args('token') token: string,
    @ClientInfo() client: ClientContext,
  ): Promise<TokenPayload> {
    return TraceRunner.run('Verify Magic Link Resolver', async () => {
      const tokenPayload = await this.authService.loginWithMagicLink(
        token,
        client,
      );
      return tokenPayload;
    });
  }
}
