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
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { RequestMeta } from '../models/dtos/request-meta.dto.js';
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
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { CookieAuthGuard, CurrentUser, CurrentUserData } from '@omnixys/auth';
import { GqlFastifyContext, ClientInfo } from '@omnixys/context';
import { ClientInfo as ClientInfoType } from '@omnixys/contracts';
import { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { FastifyReply } from 'fastify';

/**
 * GraphQL resolver providing mutation endpoints for user authentication.
 *
 * @public
 */
@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
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
    private readonly loggerService: LoggerPlusService,
    private readonly authService: AuthWriteService,
    private readonly webAuthnService: WebAuthnService,
  ) {
    this.logger = this.loggerService.getLogger(AuthMutationResolver.name);
  }

  // @Mutation(() => TokenPayload, { name: 'login' })
  // async login2(
  //   @Args('input', { type: () => LogInInput }) input: LogInInput,
  //   @Context() ctx: GqlCtx,
  // ): Promise<TokenPayload> {
  //   const ip =
  //     (ctx.req.headers['x-forwarded-for'] as string | undefined)
  //       ?.split(',')[0]
  //       ?.trim() ??
  //     ctx.req.socket?.remoteAddress ??
  //     undefined;

  //   const userAgent = ctx.req.headers['user-agent'] ?? undefined;
  //   const acceptLanguage = ctx.req.headers['accept-language'] ?? undefined;

  //   // English comment tailored for VS:
  //   // Provide a stable client-generated ID via header for stronger device fingerprinting.
  //   const clientDeviceId =
  //     (ctx.req.headers['x-device-id'] as string | undefined) ?? undefined;

  //   return this.authService.loginWithRisk(input.username, input.password, {
  //     ip,
  //     userAgent,
  //     acceptLanguage,
  //     clientDeviceId,
  //   });
  // }

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
  async credentialsLogin(
    @Args('input', { type: () => LogInInput }) input: LogInInput,
  ): Promise<TokenPayload> {
    // const res = ctx?.reply;
    this.logger.debug('login: input=%o', input);

    const { username, password } = input;

    const result = await this.authService.login({ username, password });
    if (!result) {
      throw new BadUserInputException('Invalid username or password.');
    }

    // gqlSetTokens(res, result.accessToken ?? '', result.expiresIn * 1000);
    return result;
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
    this.logger.debug(
      '[authentication-mutation.resolver.ts] Refresh %s accessToken...',
      user.username,
    );

    const refreshToken = user.refresh_token;

    const result = await this.authService.refresh(refreshToken);
    if (!result) {
      throw new BadUserInputException('Invalid or expired refresh token.');
    }

    this.logger.info('[authentication-mutation.resolver.ts] Refresh Success!');
    return result;
  }

  /**
   * Logs out a user by invalidating their refresh token
   * and clearing all authentication cookies.
   *
   * @param ctx - GraphQL context containing the HTTP response.
   * @returns {@link SuccessPayload} indicating operation status.
   */
  @Mutation(() => SuccessPayload, { name: 'logout' })
  async logout(@Context() ctx: GqlFastifyContext): Promise<SuccessPayload> {
    const res: FastifyReply = ctx?.reply;
    const value = res?.cookies?.refresh_token;
    await this.authService.logout(value);
    return { ok: true, message: 'Successfully logged out.' };
  }

  /* =====================================================
     STEP 1 – Generate Options
  ===================================================== */

  @Mutation(() => JsonScalar)
  async generatePasswordlessOptions(@Args('email') email: string) {
    return this.webAuthnService.generatePasswordlessOptions(email);
  }

  @Mutation(() => JsonScalar)
  async generateWebAuthnAuthOptions() {
    return this.webAuthnService.generateDiscoverableAuthOptions();
  }

  /* =====================================================
     STEP 2 – Verify + Create Session
  ===================================================== */

  @Mutation(() => TokenPayload)
  async verifyPasswordlessAuthentication(
    @Args('response', { type: () => JsonScalar }) response: unknown,
  ): Promise<TokenPayload> {
    if (!response || typeof response !== 'object') {
      throw new BadRequestException('Invalid WebAuthn response');
    }

    const userId = await this.webAuthnService.verifyPasswordlessAuthentication(
      response as AuthenticationResponseJSON,
    );

    if (!userId) {
      throw new UnauthorizedException('Authentication failed');
    }

    const token = await this.authService.createPasswordlessSession(userId);
    return token;
  }

  @Mutation(() => TokenPayload)
  async verifyWebAuthnAuthentication(
    @Args('response', { type: () => JsonScalar }) response: unknown,
  ): Promise<TokenPayload> {
    if (!response || typeof response !== 'object') {
      throw new BadRequestException('Invalid WebAuthn response');
    }

    const userId = await this.webAuthnService.verifyDiscoverableAuthentication(
      response as AuthenticationResponseJSON,
    );

    if (!userId) {
      throw new UnauthorizedException('Authentication failed');
    }

    const token = await this.authService.createPasswordlessSession(userId);
    return token;
  }

  @Mutation(() => TokenPayload)
  async loginTotp(@Args('input') input: LoginTotpInput): Promise<TokenPayload> {
    const token = await this.authService.loginWithTotp(
      input.username,
      input.code,
    );
    return token;
  }

  @Mutation(() => Boolean)
  async sendMagicLink(
    @Args('email') email: string,
    @ClientInfo() client: ClientInfoType,
  ): Promise<boolean> {
    try {
      const context: RequestMeta = {
        ip: client.ip,
        device: client.device,
        locale: client.locale,
        location: client.location,
      };

      void this.authService.requestMagicLink(email, context);
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
  }

  @Mutation(() => TokenPayload)
  async verifyMagicLink(@Args('token') token: string): Promise<TokenPayload> {
    const tokenPayload = await this.authService.loginWithMagicLink(token);
    return tokenPayload;
  }
}
