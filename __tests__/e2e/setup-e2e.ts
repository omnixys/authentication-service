import 'reflect-metadata';

// 🔥 KEIN AppModule import hier!

import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';

import { createKafkaContainer } from '../testcontainers/kafka.container.js';
import { createKeycloakContainer } from '../testcontainers/keycloak.container.js';
import { createPostgresContainer } from '../testcontainers/postgres.container.js';
import { TempoContainer } from '../testcontainers/tempo.container.js';
import { createValkeyContainer } from '../testcontainers/valkey.container.js';

let app: NestFastifyApplication;

let pgContainer: any;
let valkeyContainer: any;
let kafkaContainer: any;
let keycloakContainer: any;
let tempoContainer: any;

export async function createTestApp() {
  console.log('🚀 Starting Postgres...');
  const pg = await createPostgresContainer();
  pgContainer = pg.container;
  console.log('✅ Postgres ready');

  console.log('🚀 Starting Valkey...');
  const valkey = await createValkeyContainer();
  valkeyContainer = valkey.container;
  console.log('✅ Valkey ready');

  console.log('🚀 Starting Kafka...');
  const kafka = await createKafkaContainer();
  kafkaContainer = kafka.container;
  console.log('✅ Kafka ready');

    console.log('🚀 Starting Keycloak...');
    const keycloak = await createKeycloakContainer();
    keycloakContainer = keycloak.container;
  console.log('✅ Keycloak ready');
  
console.log('🚀 Starting Tempo...');

const tempo = new TempoContainer();
tempoContainer = tempo;

const { urlHttp, urlOtel } = await tempo.start();

process.env.TEMPO_URI = `${urlOtel}/v1/traces`;
process.env.TEMPO_HEALTH_URL = `${urlHttp}/metrics`;

console.log('✅ Tempo ready', {
  otel: process.env.TEMPO_URI,
});

  // 🔥 ENV HIER SETZEN (VOR IMPORT)
  process.env.DATABASE_URL = pg.url;
  process.env.VALKEY_URL = valkey.url;
  process.env.VALKEY_PASSWORD = valkey.password;
  process.env.KAFKA_BROKER = kafka.broker;
  process.env.KAFKAJS_NO_PARTITIONER_WARNING = '1';

  process.env.KC_URL = keycloak.url;
  process.env.KC_REALM = keycloak.realm;
  process.env.KC_CLIENT_ID = keycloak.clientId;
  process.env.KC_CLIENT_SECRET = keycloak.clientSecret;

  console.log('🔥 ENV:', {
    DATABASE_URL: process.env.DATABASE_URL,
    VALKEY_URL: process.env.VALKEY_URL,
    KAFKA_BROKER: process.env.KAFKA_BROKER,
  });

delete (global as any).env;

// 🔥 DANN import
const { AppModule } = await import('../../src/app.module.js');

  console.log('🚀 Bootstrapping Nest...');

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleRef.createNestApplication(new FastifyAdapter());

  await app.init();
  await app.getHttpAdapter().getInstance().ready();

  console.log('✅ Nest ready');

  return { app };
}

export async function shutdownTestApp() {
  if (app) await app.close();
  if (pgContainer) await pgContainer.stop();
  if (valkeyContainer) await valkeyContainer.stop();
  if (kafkaContainer) await kafkaContainer.stop();
  if (keycloakContainer) await keycloakContainer.stop();
  if (tempoContainer) await tempoContainer.stop()
}
