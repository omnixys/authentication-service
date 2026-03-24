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

import { AdminModule } from './admin/admin.module.js';
import { AuthenticationModule } from './authentication/authentication.module.js';
import { BannerService } from './banner.service.js';
import { env } from './config/env.js';
import { ScalarsModule } from './core/scalars/scalar.module.js';
import { HealthModule } from './health/health.module.js';
import { ApolloFederationDriver, ApolloFederationDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { GraphQLModule } from '@nestjs/graphql';
import { GqlFastifyContext } from '@omnixys/context';
import { KafkaModule } from '@omnixys/kafka';
import { LoggerModule } from '@omnixys/logger';
import { ObservabilityModule } from '@omnixys/observability';

const { SCHEMA_TARGET, SERVICE, KAFKA_BROKER, TEMPO_URI } = env;

@Module({
  imports: [
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
        port: 9464,
        enabled: true,
      },
    }),

    LoggerModule.forRoot({
      serviceName: SERVICE,

      kafka: {
        enabled: true,
        topic: 'logstream.logs',
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
    // GraphQLModule.forRoot<ApolloDriverConfig>(graphQlModuleOptions),
    ConfigModule.forRoot({ isGlobal: true }),
    GraphQLModule.forRootAsync<ApolloFederationDriverConfig>({
      driver: ApolloFederationDriver,

      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        // autoSchemaFile: join(process.cwd(), 'dist/schema.gql'),
        autoSchemaFile:
          SCHEMA_TARGET === 'tmp'
            ? { path: '/tmp/schema.gql', federation: 2 }
            : SCHEMA_TARGET === 'false'
              ? false
              : { path: 'dist/schema.gql', federation: 2 },
        sortSchema: true,
        playground: cfg.get('GRAPHQL_PLAYGROUND') === 'true',
        csrfPrevention: false,
        introspection: true,

        context: ({ req, reply }: GqlFastifyContext) => ({
          req,
          reply,
        }),
      }),
    }),
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
