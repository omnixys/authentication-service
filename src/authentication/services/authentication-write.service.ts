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

import { keycloakConfig, paths } from '../../config/keycloak.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import type { KeycloakToken } from '../models/dtos/kc-token.dto.js';
import { RequestMeta } from '../models/dtos/request-meta.dto.js';
import { AuthContext } from '../models/entitys/login-context.js';
import type { LogInInput } from '../models/inputs/log-in.input.js';
import { toToken } from '../models/mappers/token.mapper.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { LockoutService } from './lockout.service.js';
import { AuthenticateReadService } from './read.service.js';
import { TotpService } from './totp.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache';
import { KafkaProducerService, KafkaTopics } from '@omnixys/kafka';
import { OmnixysLogger } from '@omnixys/logger';
import { AccessBlockedException, DeviceService, FingerprintService, HashService, RiskEngineService, RiskMemoryService, StepUpRequiredException, ZeroTrustService } from '@omnixys/security';
import { randomBytes } from 'crypto';

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
    private readonly risk: RiskEngineService,
    private readonly deviceService: DeviceService,
    private readonly fingerPrintService: FingerprintService,
    private readonly prisma: PrismaService,
    private readonly cache: ValkeyService,
    private readonly kafka: KafkaProducerService,
    private readonly totpService: TotpService,
    private readonly lockout: LockoutService,
    private readonly readService: AuthenticateReadService,
    private readonly riskMemory: RiskMemoryService,
    private readonly hashService: HashService,
    private readonly zeroTrustService: ZeroTrustService,
  ) {
    super(logger, http);
  }

  /**
   * Password-Login (ROPC).
   * @returns TokenPayload oder null (bei invalid_grant)
   */
  async login(
    input: LogInInput & {
      ip?: string;
      userAgent?: string;
      acceptLanguage?: string;
      clientDeviceId?: string;
    },
  ): Promise<TokenPayload> {
    const { username, password } = input;

    if (!username || !password) {
      throw new UnauthorizedException('username oder passwort fehlt!');
    }

    const userId = (await this.readService.findByUsername(username)).id;

    const riskResult = await this.zeroTrustService.evaluate({
      userId,
      ip: input.ip,
      userAgent: input.userAgent,
      acceptLanguage: input.acceptLanguage,
      clientDeviceId: input.clientDeviceId,

      isPasswordless: false,
      isResetFlow: false,
    });

    if (riskResult.decision === 'BLOCK') {
      throw new AccessBlockedException(riskResult.reasons);
    }

    if (riskResult.decision === 'STEP_UP') {
      throw new StepUpRequiredException(riskResult.stepUp!, riskResult.reasons);
    }

    try {
      const body = new URLSearchParams({
        grant_type: 'password',
        username,
        password,
        scope: 'openid',
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
        await this.riskMemory.incrementFailures(userId);

        throw new UnauthorizedException('username oder passwort falsch!');
      }

      await this.riskMemory.resetFailures(userId); 

      if (input.ip) {
        await this.riskMemory.storeLastIp(userId, input.ip);
      }

      await this.deviceService.register(userId, input.clientDeviceId ?? 'unknown');

      return toToken(data);
    } catch (err) {
      // zusätzliche Sicherheit (Timing / Side-channel)
      await this.hashService.dummyVerify();
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
  async logout(refreshToken: string | undefined): Promise<void> {
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
  }

  async createPasswordlessSession(userId: string): Promise<TokenPayload> {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: keycloakConfig.clientId,
      client_secret: keycloakConfig.clientSecret,
    });

    const serviceToken = await this.kcRequest<KeycloakToken>('post', paths.accessToken, {
      data: body.toString(),
      headers: this.loginHeaders,
      adminAuth: false,
    });

    // Jetzt impersonation:
    const exchangeBody = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: keycloakConfig.clientId,
      subject_token: serviceToken.access_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_subject: userId,
      scope: 'openid profile email',
    });

    const exchanged = await this.kcRequest<KeycloakToken>('post', paths.accessToken, {
      data: exchangeBody.toString(),
      headers: this.loginHeaders,
      adminAuth: false,
    });

    return toToken(exchanged);
  }

  /**
   * Password login + adaptive risk.
   */
  async loginWithRisk(username: string, password: string, ctx: AuthContext): Promise<TokenPayload> {
    // 1) Perform Keycloak login
    const token = await this.login({ username, password });

    // 2) Ensure local auth user exists (your DB, not Keycloak)
    const email = username; // you use email as username
    const user =
      (await this.prisma.authUser.findUnique({ where: { email } })) ??
      (await this.prisma.authUser.create({
        data: {
          email,
          username,
          // mfaPreference default NONE
        },
      }));

    // 3) Evaluate risk
    const risk = await this.risk.evaluate({
      userId: user.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      acceptLanguage: ctx.acceptLanguage,
      clientDeviceId: ctx.clientDeviceId,
      isPasswordless: false,
      isResetFlow: false,
      failedAttempts: user.failedAttempts,
    });

    if (risk.decision === 'BLOCK') {
      // English comment tailored for VS:
      // Fail closed on high risk and avoid leaking details.
      throw new UnauthorizedException('Login blocked');
    }

    if (risk.decision !== 'STEP_UP') {
      // English comment tailored for VS:
      // In v1 we hard-fail and require a step-up flow.
      // In v2 return a StepUpRequired payload and persist a temporary step-up session.
      throw new UnauthorizedException(`Step-up required: ${risk.decision}`);
    }

    // 4) Success → reset failures (optional)
    if (user.failedAttempts !== 0) {
      await this.prisma.authUser.update({
        where: { id: user.id },
        data: { failedAttempts: 0, lockedUntil: null },
      });
    }

    // 5) (Optional) fingerprint is computed but not stored here.
    void this.fingerPrintService.create({
      ip: ctx.ip ?? 'unknown',
      userAgent: ctx.userAgent ?? 'unknown',
      acceptLanguage: ctx.acceptLanguage,
      clientDeviceId: ctx.clientDeviceId ?? 'unknown',
    });

    return token;
  }

  async loginWithTotp(username: string, code: string): Promise<TokenPayload> {
    if (!username || !code) {
      throw new UnauthorizedException('Missing credentials');
    }

    const user = await this.prisma.authUser.findUnique({
      where: { email: username },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const valid = await this.totpService.verifyForUser(user.id, code);

    if (!valid) {
      throw new UnauthorizedException('Invalid TOTP code');
    }

    // create session via token exchange
    return this.createPasswordlessSession(user.id);
  }

  async requestMagicLink(email: string, context: RequestMeta): Promise<boolean> {
    this.logger.debug('requesting magic link for email %s', email);

    await this.lockout.checkIpRateLimit(context?.ip, 'magic-link');

    const user = await this.prisma.authUser.findUnique({
      where: { email },
    });

    // Prevent user enumeration
    if (!user) {
      return true;
    }

    // 32 bytes → 64 hex chars
    const token = randomBytes(32).toString('hex');

    const payload = {
      userId: user.id,
      email,
      createdAt: new Date().toISOString(),
      ip: context.ip,
    };

    await this.cache.set(
      ValkeyKey.magicLinkToken,
      {
        token,
        payload: JSON.stringify(payload),
      },
      5 * 60,
    );

    void this.kafka.send({
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
        operation: ' sending Magic Link Email Request tu User',
        version: '1',
        type: 'EVENT',
      },
    });

    return true;
  }

  async loginWithMagicLink(token: string): Promise<TokenPayload> {
    if (!token || token.length < 32) {
      throw new UnauthorizedException('Invalid token');
    }

    // Atomic read + delete
    const raw = await this.cache.get(ValkeyKey.magicLinkToken, token);
    if (!raw) {
      throw new UnauthorizedException('Invalid or expired magic link');
    }

    const payload = JSON.parse(raw) as {
      userId: string;
      email: string;
      ip?: string;
    };

    await this.cache.delete(ValkeyKey.magicLinkToken, token);

    // Optional: additional risk evaluation
    // await this.risk.evaluate({ ... });

    return this.createPasswordlessSession(payload.userId);
  }
}
