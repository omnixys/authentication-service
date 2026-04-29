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

import 'dotenv/config';
import process from 'node:process';

/**
 * Environment variable configuration for the Node-based server.
 *
 * This file centralizes all environment parameters provided
 * through `.env` or system variables.
 *
 * @remarks
 * - All values are explicitly typed.
 * - Missing variables get sensible defaults (only for DEV).
 * - Booleans are converted correctly from "true"/"false" strings.
 */
export const env = {
  /**
   * Environment type:
   * - `production` → Cloud/Production mode
   * - `development` → Local development
   * - `test` → Test execution
   */
  NODE_ENV: process.env.NODE_ENV ?? 'development',

  SCHEMA_TARGET: process.env.SCHEMA_TARGET ?? 'true',

  /** Default log settings */
  LOG_DEFAULT: process.env.LOG_DEFAULT === 'true',
  LOG_DIRECTORY: process.env.LOG_DIRECTORY ?? 'log',
  LOG_FILE_DEFAULT_NAME: process.env.LOG_FILE_DEFAULT_NAME ?? 'server.log',
  LOG_PRETTY: process.env.LOG_PRETTY === 'true',
  LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',

  /** HTTPS enable flag */
  HTTPS: process.env.HTTPS === 'true',

  /** Path to key/certificate files */
  KEYS_PATH: process.env.KEYS_PATH ?? './keys',

  /** Tempo tracing endpoint */
  TEMPO_URI: process.env.TEMPO_URI ?? 'http://localhost:4318/v1/traces',

  /** Port on which the Node/NestJS server runs */
  PORT: Number(process.env.PORT ?? 4000),

  /** Keycloak / OAuth client configuration */
  KC_CLIENT_SECRET: process.env.KC_CLIENT_SECRET ?? '',
  KC_URL: process.env.KC_URL ?? 'http://localhost:18080/auth',
  KC_REALM: process.env.KC_REALM ?? 'camunda-platform',
  KC_CLIENT_ID: process.env.KC_CLIENT_ID ?? 'camunda-identity',
  KC_ADMIN_USERNAME: process.env.KC_ADMIN_USERNAME ?? 'admin',
  KC_ADMIN_PASSWORD: process.env.KC_ADMIN_PASSWORD ?? 'admin',

  /** Kafka configuration */
  KAFKA_BROKER: process.env.KAFKA_BROKER ?? 'localhost:9092',
  SERVICE: process.env.SERVICE ?? 'SERVICE',

  /** Health endpoints */
  KEYCLOAK_HEALTH_URL: process.env.KEYCLOAK_HEALTH_URL ?? '',
  TEMPO_HEALTH_URL: process.env.TEMPO_HEALTH_URL ?? '',
  PROMETHEUS_HEALTH_URL: process.env.PROMETHEUS_HEALTH_URL ?? '',

  COOKIE_SECRET: process.env.COOKIE_SECRET ?? 'omnixys-default-secret',
  REDIS_PC_JWE_KEY: process.env.REDIS_PC_JWE_KEY ?? '',
  PC_JWE_KEY: process.env.PC_JWE_KEY ?? '',
  PC_TTL_SEC: Number(process.env.PC_TTL_SEC ?? 60 * 60 * 24 * 30),
  VALKEY_URL: process.env.VALKEY_URL ?? 'valkey://localhost:6380',
  VALKEY_PASSWORD: process.env.VALKEY_PASSWORD ?? 'DeinStarkesPasswort',

  DATABASE_URL: process.env.DATABASE_URL ?? 'DATABASE_URL',
  DATABASE_URL_LOCALE: process.env.DATABASE_URL_LOCALE ?? 'DATABASE_URL_LOCALE',
  SHADOW_DATABASE_URL: process.env.SHADOW_DATABASE_URL ?? 'SHADOW_DATABASE_URL',

  RESET_TOKEN_HMAC_SECRET:
    process.env.RESET_TOKEN_HMAC_SECRET ?? 'omnixys-reset-secret',
  DEVICE_FINGERPRINT_HMAC_SECRET:
    process.env.DEVICE_FINGERPRINT_HMAC_SECRET ??
    'omnixys-device-fingerprint-secret',
  MAGIC_LINK_HMAC_SECRET:
    process.env.MAGIC_LINK_HMAC_SECRET ?? 'omnixys-magic-link-secret',
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY ?? 'omnixys-encryption-key',
  FINGERPRINT_SECRET:
    process.env.FINGERPRINT_SECRET ?? 'omnixys-fingerprint-secret',
} as const;

/**
 * Debug output:
 * Print all environment variables in non-production environments.
 */
if (process.env.NODE_ENV !== 'production') {
  console.debug('================= ENVIRONMENT VARIABLES =================');
  console.debug(JSON.stringify(env, null, 2));
  console.debug('==========================================================');
}
