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
import { KafkaProducerService } from '../../kafka/kafka-producer.service.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { ValkeyKey } from '../../valkey/valkey.keys.js';
import { ValkeyService } from '../../valkey/valkey.service.js';
import type { KeycloakToken } from '../models/dtos/kc-token.dto.js';
import { AuthContext } from '../models/entitys/login-context.js';
import type { LogInInput } from '../models/inputs/log-in.input.js';
import { toToken } from '../models/mappers/token.mapper.js';
import type { TokenPayload } from '../models/payloads/token.payload.js';
import { DeviceService } from './device.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { RiskEngineService } from './risk-engine.service.js';
import { TotpService } from './totp.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';
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
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly risk: RiskEngineService,
    private readonly deviceService: DeviceService,
    private readonly prisma: PrismaService,
    private readonly valkey: ValkeyService,
    private readonly kafka: KafkaProducerService,
    private readonly totpService: TotpService,
  ) {
    super(logger, trace, http);
  }

  /**
   * Password-Login (ROPC).
   * @returns TokenPayload oder null (bei invalid_grant)
   */
  async login({ username, password }: LogInInput): Promise<TokenPayload> {
    return this.withSpan('authentication.login', async (_span) => {
      if (!username || !password) {
        throw new UnauthorizedException('username oder passwort fehlt!');
      }
      const body = new URLSearchParams({
        grant_type: 'password',
        username,
        password,
        scope: 'openid',
      });
      const data = await this.kcRequest<KeycloakToken>(
        'post',
        paths.accessToken,
        { data: body.toString(), headers: this.loginHeaders, adminAuth: false },
        { mapTo: 'null-on-401' },
      );
      if (!data) {
        throw new UnauthorizedException('username oder passwort falsch!');
      }
      return toToken(data);
    });
  }

  /**
   * Refresh-Flow.
   */
  async refresh(refresh_token: string | undefined): Promise<TokenPayload | null> {
    return this.withSpan('authentication.refresh', async (_span) => {
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
    });
  }

  /**
   * Logout (Refresh-Token invalidieren).
   */
  async logout(refreshToken: string | undefined): Promise<void> {
    return this.withSpan('authentication.logout', async (_span) => {
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

    if (risk.decision !== 'NONE') {
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
    void this.deviceService.computeFingerprint({
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      acceptLanguage: ctx.acceptLanguage,
      clientDeviceId: ctx.clientDeviceId,
    });

    return token;
  }

  async loginWithTotp(username: string, code: string): Promise<TokenPayload> {
    return this.withSpan('authentication.login.totp', async () => {
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
    });
  }

  async requestMagicLink(
    email: string,
    ctx?: { ip?: string; userAgent?: string },
  ): Promise<boolean> {
    return this.withSpan('authentication.login.totp', async (span) => {
      this.logger.debug('requesting magic link for email %s', email);
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
        ip: ctx?.ip,
      };

      await this.valkey.client.set(ValkeyKey.magicLinkToken(token), JSON.stringify(payload), {
        PX: 15 * 60 * 1000,
      });

      const sc = span.spanContext();
      void this.kafka.sendMagicLink(
        {
          email: user.email,
          token,
        },
        'authentication.requestMagicLink',
        { traceId: sc.traceId, spanId: sc.spanId },
      );

      return true;
    });
  }

  async loginWithMagicLink(token: string): Promise<TokenPayload> {
    if (!token || token.length < 32) {
      throw new UnauthorizedException('Invalid token');
    }

    // Atomic read + delete
    const raw = await this.valkey.client.get(ValkeyKey.magicLinkToken(token));
    if (!raw) {
      throw new UnauthorizedException('Invalid or expired magic link');
    }

    const payload = JSON.parse(raw) as {
      userId: string;
      email: string;
      ip?: string;
    };

    await this.valkey.client.del(ValkeyKey.magicLinkToken(token));

    // Optional: additional risk evaluation
    // await this.risk.evaluate({ ... });

    return this.createPasswordlessSession(payload.userId);
  }
}
