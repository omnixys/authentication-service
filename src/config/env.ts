import 'dotenv/config';
import process from 'node:process';

type EnvValue = string | number | boolean;
interface GetEnvOptions<T extends EnvValue = string> {
  required?: boolean;
  transform?: (value: string) => T;
}

function getEnv(
  key: string,
  fallback?: string,
  options?: GetEnvOptions<string>,
): string;
function getEnv<T extends EnvValue>(
  key: string,
  fallback: string,
  options: GetEnvOptions<T> & { transform: (value: string) => T },
): T;
function getEnv(
  key: string,
  fallback?: string,
  options?: GetEnvOptions,
): EnvValue {
  const raw = process.env[key];
  if (!raw) {
    if (options?.required && process.env.NODE_ENV === 'production') {
      throw new Error(`[ENV] Missing required env: ${key}`);
    }
    return options?.transform && fallback !== undefined
      ? options.transform(fallback)
      : (fallback ?? '');
  }
  return options?.transform ? options.transform(raw) : raw;
}

const toBool = (value: string): boolean => value === 'true';
const toNumber = (value: string): number => Number(value);

export const env = {
  NODE_ENV: getEnv('NODE_ENV', 'development'),
  SCHEMA_TARGET: getEnv('SCHEMA_TARGET', 'true'),
  LOG_DEFAULT: getEnv('LOG_DEFAULT', 'false', { transform: toBool }),
  LOG_DIRECTORY: getEnv('LOG_DIRECTORY', 'log'),
  LOG_FILE_DEFAULT_NAME: getEnv('LOG_FILE_DEFAULT_NAME', 'server.log'),
  LOG_PRETTY: getEnv('LOG_PRETTY', 'false', { transform: toBool }),
  LOG_LEVEL: getEnv('LOG_LEVEL', 'info'),
  HTTPS: getEnv('HTTPS', 'false', { transform: toBool }),
  KEYS_PATH: getEnv('KEYS_PATH', './keys'),
  TEMPO_URI: getEnv('TEMPO_URI', 'http://localhost:4318/v1/traces'),
  PORT: getEnv('PORT', '4000', { transform: toNumber }),
  KC_CLIENT_SECRET: getEnv('KC_CLIENT_SECRET', '', { required: true }),
  KC_URL: getEnv('KC_URL', 'http://localhost:18080/auth'),
  KC_REALM: getEnv('KC_REALM', 'camunda-platform'),
  KC_CLIENT_ID: getEnv('KC_CLIENT_ID', 'camunda-identity'),
  KC_ADMIN_USERNAME: getEnv('KC_ADMIN_USERNAME', 'admin', { required: true }),
  KC_ADMIN_PASSWORD: getEnv('KC_ADMIN_PASSWORD', '', { required: true }),
  KC_TLS_REJECT_UNAUTHORIZED: getEnv('KC_TLS_REJECT_UNAUTHORIZED', 'true', {
    transform: toBool,
  }),
  KAFKA_BROKER: getEnv('KAFKA_BROKER', 'localhost:9092'),
  SERVICE: getEnv('SERVICE', 'authentication-service'),
  KEYCLOAK_HEALTH_URL: getEnv('KEYCLOAK_HEALTH_URL', ''),
  TEMPO_HEALTH_URL: getEnv('TEMPO_HEALTH_URL', ''),
  PROMETHEUS_HEALTH_URL: getEnv('PROMETHEUS_HEALTH_URL', ''),
  COOKIE_SECRET: getEnv('COOKIE_SECRET', 'omnixys-development-secret', {
    required: true,
  }),
  REDIS_PC_JWE_KEY: getEnv('REDIS_PC_JWE_KEY', ''),
  PC_JWE_KEY: getEnv('PC_JWE_KEY', '', { required: true }),
  PC_TTL_SEC: getEnv('PC_TTL_SEC', String(60 * 60 * 24 * 30), {
    transform: toNumber,
  }),
  VALKEY_URL: getEnv('VALKEY_URL', 'valkey://localhost:6380'),
  VALKEY_PASSWORD: getEnv('VALKEY_PASSWORD', '', { required: true }),
  DATABASE_URL: getEnv('DATABASE_URL', '', { required: true }),
  DATABASE_URL_LOCALE: getEnv('DATABASE_URL_LOCALE', ''),
  SHADOW_DATABASE_URL: getEnv('SHADOW_DATABASE_URL', ''),
  RESET_TOKEN_HMAC_SECRET: getEnv('RESET_TOKEN_HMAC_SECRET', '', {
    required: true,
  }),
  DEVICE_FINGERPRINT_HMAC_SECRET: getEnv('DEVICE_FINGERPRINT_HMAC_SECRET', '', {
    required: true,
  }),
  MAGIC_LINK_HMAC_SECRET: getEnv('MAGIC_LINK_HMAC_SECRET', '', {
    required: true,
  }),
  ENCRYPTION_KEY: getEnv('ENCRYPTION_KEY', '', { required: true }),
  FINGERPRINT_SECRET: getEnv('FINGERPRINT_SECRET', '', { required: true }),
} as const;
