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

import { ValkeyAdapterModule } from './adapter/valkey-adapter.module.js';
import { AdminModule } from './admin/admin.module.js';
import { AuthenticationModule } from './authentication/authentication.module.js';
import { BannerService } from './banner.service.js';
import { env } from './config/env.js';
import { ScalarsModule } from './core/scalars/scalar.module.js';
import { HealthModule } from './health/health.module.js';
import { Module } from '@nestjs/common';
import { ValkeyModule } from '@omnixys/cache';
import { OmnixysGraphQLModule } from '@omnixys/graphql';
import { KafkaModule } from '@omnixys/kafka';
import { LoggerModule } from '@omnixys/logger';
import { ObservabilityModule } from '@omnixys/observability';
import { SecurityModule } from '@omnixys/security';

const {
  SCHEMA_TARGET,
  SERVICE,
  KAFKA_BROKER,
  TEMPO_URI,
  VALKEY_URL,
  VALKEY_PASSWORD,
  PC_JWE_KEY,
  KC_REALM,
  KC_URL,
  RESET_TOKEN_HMAC_SECRET,
  DEVICE_FINGERPRINT_HMAC_SECRET,
  MAGIC_LINK_HMAC_SECRET,
  ENCRYPTION_KEY,
  FINGERPRINT_SECRET,
} = env;

@Module({
  imports: [
    ValkeyModule.forRoot({
      serviceName: `${SERVICE}-service`,
      url: VALKEY_URL,
      password: VALKEY_PASSWORD,

      pubSub: { enabled: true },
      streams: { enabled: true },
    }),

    OmnixysGraphQLModule.forRoot({
      autoSchemaFile:
        SCHEMA_TARGET === 'tmp'
          ? { path: '/tmp/schema.gql', federation: 2 }
          : SCHEMA_TARGET === 'false'
            ? false
            : { path: 'dist/schema.gql', federation: 2 },
      sortSchema: true,
    }),

    SecurityModule.forRoot({
      jwt: {
        issuer: `${KC_URL}/realms/${KC_REALM}`,
        jwksUri: `${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/certs`,
      },

      jwe: {
        keys: [
          {
            kid: 'v1',
            value: PC_JWE_KEY,
          },
        ],
      },

      session: {
        ttlMs: 1000 * 60 * 60,
      },

      rateLimit: {
        enabled: true,
      },

      hash: {
        hmacResetToken: RESET_TOKEN_HMAC_SECRET,
        hmacDeviceFingerprint: DEVICE_FINGERPRINT_HMAC_SECRET,
        hmacMagicLink: MAGIC_LINK_HMAC_SECRET,

        encryptionKey: ENCRYPTION_KEY,
      },

      zeroTrust: {
        imports: [ValkeyAdapterModule],
      },

      fingerprintSecret: FINGERPRINT_SECRET,
      globalGuards: false,
    }),
    KafkaModule.forRoot({
      clientId: `${SERVICE}-service`,
      brokers: [KAFKA_BROKER],
      groupId: `${SERVICE}-consumer`,
    }),

    ObservabilityModule.forRoot({
      serviceName: SERVICE,

      otel: {
        endpoint: TEMPO_URI,
        transport: 'http',
        samplingRatio: 1,
      },

      metrics: {
        port: 17501,
        enabled: true,
      },
    }),

    LoggerModule.forRoot({
      serviceName: SERVICE,

      kafka: {
        enabled: true,
        topic: 'logstream.input',
      },
      batch: {
        enabled: true,
        maxSize: 50,
        flushInterval: 2000,
      },
    }),

    AdminModule,
    HealthModule,
    AuthenticationModule,
    ScalarsModule,
  ],
  controllers: [],
  providers: [BannerService],
})
// implements NestModule
export class AppModule {
  // configure(consumer: MiddlewareConsumer): void {
  //   consumer.apply(RequestLoggerMiddleware).forRoutes('*');
  // }
}
