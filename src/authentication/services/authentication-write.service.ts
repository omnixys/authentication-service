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

import { AnalyticsOutboxService } from '../../analytics/analytics-outbox.service.js';
import { authClientConfig, keycloakConfig, paths } from '../../config/keycloak.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  AuthenticationInputException,
  AuthenticationUserNotFoundException,
} from '../errors/authentication.error.js';
import { GuestMagicLinkMetricsService } from '../metrics/guest-magic-link.metrics.service.js';
import type { KeycloakToken } from '../models/dtos/kc-token.dto.js';
import type { LogInInput } from '../models/inputs/log-in.input.js';
import { LoginTotpInput } from '../models/inputs/login-totp.input.js';
import { toToken } from '../models/mappers/token.mapper.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { LockoutService } from './lockout.service.js';
import { AuthenticateReadService } from './read.service.js';
import { TotpService } from './totp.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, Optional } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache-ts';
import type { ClientContext } from '@omnixys/context-ts';
import type {
  GuestMagicLinkNotificationDTO,
  GuestMagicLinkRequestDTO,
} from '@omnixys/contracts-ts';
import { KafkaProducerService, KafkaTopics } from '@omnixys/kafka-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';
import {
  AccessBlockedException,
  DeviceService,
  HashService,
  InvalidCredentialsException,
  RiskMemoryService,
  StepUpRequiredException,
  ZeroTrustService,
} from '@omnixys/security-ts';

export interface RequestContext {
  ip?: string;
  userAgent?: string;
  acceptLanguage?: string;
  clientDeviceId?: string;
  correlationId?: string;
  traceId?: string;
}
/**
 * @file Mutierende Operationen gegen Keycloak (Authentication-Flows & User-Mutationen).
 *  - login/refresh/logout
 *  - signUp / update / password / delete
 *  - Attribute & Rollen
 *  - Kafka-Events bei signUp
 */
@Injectable()
export class AuthWriteService extends AuthenticateBaseService {
  constructor(
    logger: OmnixysLogger,
    http: HttpService,
    private readonly deviceService: DeviceService,
    private readonly prisma: PrismaService,
    private readonly cache: ValkeyService,
    private readonly kafka: KafkaProducerService,
    private readonly totpService: TotpService,
    private readonly lockout: LockoutService,
    private readonly readService: AuthenticateReadService,
    private readonly riskMemory: RiskMemoryService,
    private readonly hashService: HashService,
    private readonly zeroTrustService: ZeroTrustService,
    private readonly analyticsOutbox: AnalyticsOutboxService,
    @Optional() private readonly magicLinkMetrics?: GuestMagicLinkMetricsService,
  ) {
    super(logger, http);
  }

  /**
   * Resolves the internal Omnixys user id (U, UUIDv7) from a Keycloak subject (K).
   * Keycloak returns K; our AuthUser table stores the mapping K -> U in keycloak_sub.
   * Must be called before any identity-sensitive persistence or analytics.
   */
  private async resolveInternalUserId(keycloakSub: string): Promise<string> {
    const authUser = await this.prisma.authUser.findUniqueOrThrow({
      where: { keycloakSub },
      select: { id: true },
    });
    return authUser.id;
  }

  /**
   * Password-Login (ROPC).
   * @returns TokenPayload oder null (bei invalid_grant)
   */
  async passwordLogin(input: LogInInput & RequestContext): Promise<TokenPayload> {
    const { username, password } = input;

    this.logger.info('auth.login.start: %o', {
      phase: 'login.start',
      operation: 'passwordLogin',
    });

    if (!username || !password) {
      throw new InvalidCredentialsException();
    }

    let keycloakSub: string;
    const userLookupStartedAt = Date.now();
    this.logger.info('auth.login.phase.start: %o', {
      phase: 'keycloak.user-lookup',
      endpoint: paths.users,
    });
    try {
      keycloakSub = (await this.readService.findByUsername(username)).id;
      this.logger.info('auth.login.phase.success: %o', {
        phase: 'keycloak.user-lookup',
        endpoint: paths.users,
        durationMs: Date.now() - userLookupStartedAt,
      });
    } catch (error) {
      await this.hashService.dummyVerify();
      if (error instanceof AuthenticationUserNotFoundException) {
        this.logger.info('auth.login.phase.failure: %o', {
          phase: 'keycloak.user-lookup',
          endpoint: paths.users,
          durationMs: Date.now() - userLookupStartedAt,
          result: 'user-not-found',
        });
        throw new InvalidCredentialsException();
      }
      this.logger.warn('auth.login.phase.failure: %o', {
        phase: 'keycloak.user-lookup',
        endpoint: paths.users,
        durationMs: Date.now() - userLookupStartedAt,
        result: 'provider-error',
      });
      throw error;
    }

    // Resolve internal Omnixys user id (U) from Keycloak subject (K).
    const internalUserId = await this.resolveInternalUserId(keycloakSub);

    // const riskResult = await this.zeroTrustService.evaluate({
    //   userId: internalUserId,
    //   ip: input.ip,
    //   userAgent: input.userAgent,
    //   acceptLanguage: input.acceptLanguage,
    //   clientDeviceId: input.clientDeviceId,
    //   isPasswordless: false,
    //   isResetFlow: false,
    // });

    // if (riskResult.decision === 'BLOCK') {
    //   throw new AccessBlockedException(riskResult.reasons);
    // }

    // if (riskResult.decision === 'STEP_UP') {
    //   throw new StepUpRequiredException(riskResult.stepUp!, riskResult.reasons);
    // }

    const passwordGrantStartedAt = Date.now();
    try {
      const body = new URLSearchParams({
        grant_type: 'password',
        client_id: keycloakConfig.clientId,
        client_secret: keycloakConfig.clientSecret,
        username,
        password,
        scope: 'openid',
      });
      this.logger.info('auth.login.phase.start: %o', {
        phase: 'keycloak.password-grant',
        endpoint: paths.accessToken,
        operation: 'passwordLogin',
      });

      const data = await this.kcRequest<KeycloakToken>(
        'post',
        paths.accessToken,
        {
          data: body.toString(),
          headers: this.loginHeaders,
          adminAuth: false,
        },
        { mapTo: 'null-on-401' },
      );

      if (!data) {
        await this.riskMemory.incrementFailures(internalUserId);

        throw new InvalidCredentialsException();
      }

      this.logger.info('auth.login.phase.success: %o', {
        phase: 'keycloak.password-grant',
        endpoint: paths.accessToken,
        durationMs: Date.now() - passwordGrantStartedAt,
      });

      await this.riskMemory.resetFailures(internalUserId);

      if (input.ip) {
        await this.riskMemory.storeLastIp(internalUserId, input.ip);
      }

      await this.deviceService.register(internalUserId, input.clientDeviceId ?? 'unknown');

      await this.recordLoginFact(internalUserId, input.ip, true, 'password');
      return toToken(data);
    } catch (err) {
      // zusätzliche Sicherheit (Timing / Side-channel)
      await this.hashService.dummyVerify();
      this.logger.warn('auth.login.phase.failure: %o', {
        phase: 'keycloak.password-grant',
        endpoint: paths.accessToken,
        durationMs: Date.now() - passwordGrantStartedAt,
        result:
          err instanceof InvalidCredentialsException ? 'invalid-credentials' : 'provider-error',
      });
      if (err instanceof InvalidCredentialsException) {
        await this.recordLoginFact(
          internalUserId,
          input.ip,
          false,
          'password',
          'INVALID_CREDENTIALS',
        );
      }
      throw err;
    }
  }

  /**
   * Refresh-Flow.
   */
  async refresh(refresh_token: string | undefined): Promise<TokenPayload | null> {
    if (!refresh_token) {
      return null;
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token,
    });
    const data = await this.kcRequest<KeycloakToken>(
      'post',
      paths.accessToken,
      { data: body.toString(), headers: this.loginHeaders, adminAuth: false },
      { mapTo: 'null-on-401' },
    );
    if (!data) {
      return null;
    }
    return toToken(data);
  }

  /**
   * Logout (Refresh-Token invalidieren).
   */
  async logout(refreshToken: string | undefined, userId: string): Promise<void> {
    if (!refreshToken) {
      return;
    }
    const body = new URLSearchParams({
      client_id: keycloakConfig.clientId ?? '',
      refresh_token: refreshToken,
    });
    await this.kcRequest('post', paths.logout, {
      data: body.toString(),
      headers: this.loginHeaders,
      adminAuth: false,
    });
    await this.prisma.$transaction(async (tx) => {
      await tx.userPresence.upsert({
        where: { userId },
        create: { userId, isOnline: false },
        update: { isOnline: false, lastSeenAt: new Date() },
      });
      await this.analyticsOutbox.enqueue(tx, 'authentication.logout.succeeded.v1', {
        eventName: 'LogoutSucceeded',
        aggregateId: userId,
        aggregateType: 'authentication-session',
        subjectId: userId,
        properties: {},
      });
    });
  }

  private async recordLoginFact(
    userId: string,
    ip: string | undefined,
    succeeded: boolean,
    method: string,
    reason?: string,
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const history = await tx.loginHistory.create({
        data: {
          userId,
          ip: ip ?? 'unknown',
          succeeded,
          reason,
        },
      });
      await this.analyticsOutbox.enqueue(
        tx,
        succeeded ? 'authentication.login.succeeded.v1' : 'authentication.login.failed.v1',
        {
          eventName: succeeded ? 'LoginSucceeded' : 'LoginFailed',
          aggregateId: history.id,
          aggregateType: 'login-attempt',
          subjectId: userId,
          properties: { method, ...(reason ? { reason } : {}) },
        },
      );
    });
  }

  async createPasswordlessSession(
    internalUserId: string,
    context: RequestContext,
  ): Promise<TokenPayload> {
    // Resolve Keycloak subject (K) for token-exchange impersonation.
    const authUser = await this.prisma.authUser.findUniqueOrThrow({
      where: { id: internalUserId },
      select: { keycloakSub: true },
    });
    const keycloakSub = authUser.keycloakSub;

    const riskResult = await this.zeroTrustService.evaluate({
      userId: internalUserId,
      ip: context.ip,
      userAgent: context.userAgent,
      acceptLanguage: context.acceptLanguage,
      clientDeviceId: context.clientDeviceId,

      isPasswordless: true,
      isResetFlow: false,
    });

    if (riskResult.decision === 'BLOCK') {
      throw new AccessBlockedException(riskResult.reasons);
    }

    if (riskResult.decision === 'STEP_UP') {
      const stepUpMethod = riskResult.stepUp;
      if (!stepUpMethod) {
        throw new AuthenticationInputException('step-up-method-missing');
      }
      throw new StepUpRequiredException(stepUpMethod, riskResult.reasons);
    }

    try {
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: authClientConfig.clientId,
        client_secret: authClientConfig.clientSecret,
      });

      const serviceToken = await this.kcRequest<KeycloakToken>('post', paths.accessToken, {
        data: body.toString(),
        headers: this.authClientLoginHeaders,
        adminAuth: false,
      });

      // Jetzt impersonation: requested_subject muss Keycloak-Subject (K) sein.
      const exchangeBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: authClientConfig.clientId,
        subject_token: serviceToken.access_token,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        requested_subject: keycloakSub,
        scope: 'openid profile email',
      });

      const exchanged = await this.kcRequest<KeycloakToken>('post', paths.accessToken, {
        data: exchangeBody.toString(),
        headers: this.authClientLoginHeaders,
        adminAuth: false,
      });

      if (!exchanged) {
        await this.riskMemory.incrementFailures(internalUserId);

        throw new InvalidCredentialsException('Token exchange failed');
      }

      await this.riskMemory.resetFailures(internalUserId);

      if (context.ip) {
        await this.riskMemory.storeLastIp(internalUserId, context.ip);
      }

      await this.deviceService.register(internalUserId, context.clientDeviceId ?? 'unknown');

      return toToken(exchanged);
    } catch (err) {
      await this.hashService.dummyVerify();
      throw err;
    }
  }

  async loginWithTotp(input: LoginTotpInput & RequestContext): Promise<TokenPayload> {
    const { username, code } = input;

    if (!username || !code) {
      throw new InvalidCredentialsException();
    }

    let keycloakSub: string;
    try {
      keycloakSub = (await this.readService.findByUsername(username)).id;
    } catch {
      await this.hashService.dummyVerify();
      throw new InvalidCredentialsException();
    }

    // Resolve internal Omnixys user id (U) from Keycloak subject (K).
    const internalUserId = await this.resolveInternalUserId(keycloakSub);

    const riskResult = await this.zeroTrustService.evaluate({
      userId: internalUserId,
      ip: input.ip,
      userAgent: input.userAgent,
      acceptLanguage: input.acceptLanguage,
      clientDeviceId: input.clientDeviceId,

      isPasswordless: true,
      isResetFlow: false,
    });

    if (riskResult.decision === 'BLOCK') {
      throw new AccessBlockedException(riskResult.reasons);
    }

    if (riskResult.decision === 'STEP_UP') {
      const stepUpMethod = riskResult.stepUp;
      if (!stepUpMethod) {
        throw new AuthenticationInputException('step-up-method-missing');
      }
      throw new StepUpRequiredException(stepUpMethod, riskResult.reasons);
    }

    try {
      const user = await this.prisma.authUser.findUnique({
        where: { email: username },
      });

      if (!user) {
        throw new InvalidCredentialsException();
      }

      const valid = await this.totpService.verifyForUser(user.id, code);

      if (!valid) {
        throw new InvalidCredentialsException();
      }

      // await this.riskMemory.markStepUpVerified(internalUserId, {
      //   ip: input.ip,
      //   deviceId: input.clientDeviceId,
      //   userAgent: input.userAgent,
      // });

      await this.riskMemory.resetFailures(internalUserId);

      if (input.ip) {
        await this.riskMemory.storeLastIp(internalUserId, input.ip);
      }

      await this.deviceService.register(internalUserId, input.clientDeviceId ?? 'unknown');

      // create session via token exchange
      return this.createPasswordlessSession(user.id, input);
    } catch (err) {
      await this.hashService.dummyVerify();
      throw err;
    }
  }

  async requestMagicLink(email: string, context: ClientContext): Promise<boolean> {
    this.logger.debug('requesting magic link for email %s', email);

    await this.lockout.checkIpRateLimit(context?.ip, 'magic-link');

    const user = await this.prisma.authUser.findUnique({
      where: { email },
    });

    // Prevent user enumeration
    if (!user) {
      return true;
    }

    const payload = {
      userId: user.id,
      email,
      createdAt: new Date().toISOString(),
      ip: context.ip,
    };

    const token = await this.cache.set(ValkeyKey.magicLinkToken, JSON.stringify(payload), 5 * 60);

    // ActorId in den header setzen

    await this.kafka.send({
      topic: KafkaTopics.notification.sendMagicLink,
      payload: {
        email: user.email,
        token,
        locale: context.locale,
        device: context.device,
        ip: context.ip ?? 'Unkown IP Address',
        location: context.location,
        username: user.username,
      },
      meta: {
        service: 'authentication-service',
        operation: 'send magic link email',
        version: '1',
        type: 'EVENT',
      },
    });

    return true;
  }

  async requestGuestMagicLink(input: GuestMagicLinkRequestDTO): Promise<void> {
    await this.lockout.checkIpRateLimit(input.ip, 'magic-link');

    const user = await this.prisma.authUser.findUnique({
      where: { id: input.userId },
      select: { id: true, username: true },
    });
    if (!user) {
      this.logger.warn('guest_magic_link_issue: %o', {
        result: 'USER_NOT_FOUND',
        correlationId: input.correlationId,
        channel: input.channel,
      });
      return;
    }

    const token = await this.cache.set(
      ValkeyKey.magicLinkToken,
      JSON.stringify({ userId: user.id, channel: input.channel }),
      5 * 60,
    );

    const payload: GuestMagicLinkNotificationDTO = {
      ...input,
      username: user.username,
      token,
    };
    await this.kafka.send({
      topic: KafkaTopics.notification.sendGuestMagicLink,
      payload,
      meta: {
        service: 'authentication-service',
        operation: 'send guest magic link',
        version: '1',
        type: 'EVENT',
        tenantId: input.tenantId,
      },
    });
    this.magicLinkMetrics?.issue(input.channel);
    this.logger.info('guest_magic_link_issue: %o', {
      result: 'DISPATCH_QUEUED',
      correlationId: input.correlationId,
      channel: input.channel,
    });
  }

  async loginWithMagicLink(token: string, context: RequestContext): Promise<TokenPayload> {
    if (!token || token.length < 32) {
      return this.rejectMagicLink(context);
    }

    // Atomic read + delete: concurrent replays can never both create a session.
    let serialized: string | null;
    try {
      serialized = await this.cache.client.getDel(ValkeyKey.magicLinkToken.key(token));
    } catch (error) {
      this.logger.error('magic_link_verification: %o', {
        result: 'INTERNAL_FAILURE',
        correlationId: context.correlationId,
        traceId: context.traceId,
      });
      throw error;
    }
    if (serialized === null) {
      return this.rejectMagicLink(context);
    }

    let payload: {
      userId: string;
      email?: string;
      channel?: 'EMAIL' | 'WHATSAPP';
      ip?: string;
    };
    try {
      payload = JSON.parse(serialized) as typeof payload;
    } catch {
      return this.rejectMagicLink(context);
    }
    if (!payload.userId) {
      return this.rejectMagicLink(context);
    }

    const riskResult = await this.zeroTrustService.evaluate({
      userId: payload.userId,
      ip: context.ip,
      userAgent: context.userAgent,
      acceptLanguage: context.acceptLanguage,
      clientDeviceId: context.clientDeviceId,

      isPasswordless: true,
      isResetFlow: false,
    });

    if (riskResult.decision === 'BLOCK') {
      this.magicLinkMetrics?.recordVerifyError();
      this.logger.warn('magic_link_verification: %o', {
        result: 'RISK_BLOCKED',
        correlationId: context.correlationId,
        traceId: context.traceId,
      });
      throw new AccessBlockedException(riskResult.reasons);
    }

    if (riskResult.decision === 'STEP_UP') {
      const stepUpMethod = riskResult.stepUp;
      if (!stepUpMethod) {
        this.magicLinkMetrics?.recordVerifyError();
        this.logger.warn('magic_link_verification: %o', {
          result: 'STEP_UP_REJECTED',
          correlationId: context.correlationId,
          traceId: context.traceId,
        });
        throw new AuthenticationInputException('step-up-method-missing');
      }
      throw new StepUpRequiredException(stepUpMethod, riskResult.reasons);
    }

    try {
      await this.riskMemory.resetFailures(payload.userId);

      if (context.ip) {
        await this.riskMemory.storeLastIp(payload.userId, context.ip);
      }

      await this.deviceService.register(payload.userId, context.clientDeviceId ?? 'unknown');

      const session = await this.createPasswordlessSession(payload.userId, context);
      this.magicLinkMetrics?.recordVerified();
      this.logger.info('magic_link_verification: %o', {
        result: 'VERIFIED',
        correlationId: context.correlationId,
        traceId: context.traceId,
      });
      return session;
    } catch (err) {
      await this.hashService.dummyVerify();
      throw err;
    }
  }

  private rejectMagicLink(context: RequestContext): never {
    this.magicLinkMetrics?.recordVerifyError();
    this.logger.warn('magic_link_verification: %o', {
      result: 'INVALID_OR_EXPIRED',
      correlationId: context.correlationId,
      traceId: context.traceId,
    });
    throw new InvalidCredentialsException('Invalid or expired magic link');
  }
}
