import 'reflect-metadata';

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import cookie from '@fastify/cookie';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import type { StartedTestContainer } from 'testcontainers';

import { createKafkaContainer } from '../testcontainers/kafka.container.js';
import { createKeycloakContainer } from '../testcontainers/keycloak.container.js';
import { createPostgresContainer } from '../testcontainers/postgres.container.js';
import { TempoContainer } from '../testcontainers/tempo.container.js';
import { createValkeyContainer } from '../testcontainers/valkey.container.js';

let app: NestFastifyApplication | undefined;
let pgContainer: StartedTestContainer | undefined;
let valkeyContainer: StartedTestContainer | undefined;
let kafkaContainer: StartedTestContainer | undefined;
let keycloakContainer: StartedTestContainer | undefined;
let tempoContainer: TempoContainer | undefined;
const execFileAsync = promisify(execFile);

export async function createTestApp(): Promise<{ app: NestFastifyApplication }> {
  await shutdownTestApp();

  try {
    const pg = await createPostgresContainer();
    pgContainer = pg.container;

    const valkey = await createValkeyContainer();
    valkeyContainer = valkey.container;

    const kafka = await createKafkaContainer();
    kafkaContainer = kafka.container;

    const keycloak = await createKeycloakContainer();
    keycloakContainer = keycloak.container;

    tempoContainer = new TempoContainer();
    const { urlHttp, urlOtel } = await tempoContainer.start();

    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL = pg.url;
    process.env.VALKEY_URL = valkey.url;
    process.env.VALKEY_PASSWORD = valkey.password;
    process.env.KAFKA_BROKER = kafka.broker;
    process.env.KAFKAJS_NO_PARTITIONER_WARNING = '1';
    process.env.KC_URL = keycloak.url;
    process.env.KC_REALM = keycloak.realm;
    process.env.KC_CLIENT_ID = keycloak.clientId;
    process.env.KC_CLIENT_SECRET = keycloak.clientSecret;
    process.env.TEMPO_URI = `${urlOtel}/v1/traces`;
    process.env.TEMPO_HEALTH_URL = `${urlHttp}/metrics`;

    await execFileAsync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
      env: process.env,
    });

    const { AppModule } = await import('../../src/app.module.js');
    console.info('[e2e] compiling Nest module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();

    console.info('[e2e] initializing Nest application');
    app = moduleRef.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
    await app.register(cookie, { secret: process.env.COOKIE_SECRET });
    await app.init();
    console.info('[e2e] waiting for Fastify readiness');
    await app.getHttpAdapter().getInstance().ready();
    console.info('[e2e] application ready');

    return { app };
  } catch (error) {
    await shutdownTestApp();
    throw error;
  }
}

export async function shutdownTestApp(): Promise<void> {
  await settle(app?.close());
  await settle(tempoContainer?.stop());
  await settle(keycloakContainer?.stop());
  await settle(kafkaContainer?.stop());
  await settle(valkeyContainer?.stop());
  await settle(pgContainer?.stop());
  app = undefined;
  tempoContainer = undefined;
  keycloakContainer = undefined;
  kafkaContainer = undefined;
  valkeyContainer = undefined;
  pgContainer = undefined;
}

async function settle(operation: Promise<unknown> | undefined): Promise<void> {
  if (!operation) {
    return;
  }
  await operation.catch(() => undefined);
}
