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
const keycloakIssuerUrl = getEnv('KC_URL', 'http://localhost:18080/auth');

export const env = {
  NODE_ENV: getEnv('NODE_ENV', 'development'),
  PORT: getEnv('PORT', '4000', { transform: toNumber }),
  SERVICE: getEnv('SERVICE', 'authentication'),

  SCHEMA_TARGET: getEnv('SCHEMA_TARGET', 'true'),
  HTTPS: getEnv('HTTPS', 'false', { transform: toBool }),
  KEYS_PATH: getEnv('KEYS_PATH', './keys'),

  LOG_DEFAULT: getEnv('LOG_DEFAULT', 'false', { transform: toBool }),
  LOG_DIRECTORY: getEnv('LOG_DIRECTORY', 'log'),
  LOG_FILE_DEFAULT_NAME: getEnv('LOG_FILE_DEFAULT_NAME', 'server.log'),
  LOG_PRETTY: getEnv('LOG_PRETTY', 'false', { transform: toBool }),
  LOG_LEVEL: getEnv('LOG_LEVEL', 'info'),
  LOG_BATCH_ENABLE: getEnv('LOG_BATCH_ENABLE', 'true', { transform: toBool }),
  LOG_BATCH_MAX_SIZE: getEnv('LOG_BATCH_MAX_SIZE', '50', {
    transform: toNumber,
  }),
  LOG_BATCH_FLUSH_INTERVAL: getEnv('LOG_BATCH_FLUSH_INTERVAL', '2000', {
    transform: toNumber,
  }),

  OTEL_LOGS_ENABLED: getEnv('OTEL_LOGS_ENABLED', 'true', { transform: toBool }),
  OTEL_URI: getEnv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4318'),
  OTEL_TRANSPORT_MODE: getEnv('OTEL_TRANSPORT_MODE', 'http', {
    required: true,
  }),
  OTEL_SAMPLING_RATIO: getEnv('OTEL_SAMPLING_RATIO', '1', {
    transform: toNumber,
  }),
  TEMPO_URI: getEnv('TEMPO_URI', 'http://localhost:4318'),
  PROMETHEUS_ENABLE: getEnv('PROMETHEUS_ENABLE', 'true', { transform: toBool }),
  PROMETHEUS_PORT: getEnv('PROMETHEUS_PORT', '17501', { transform: toNumber }),

  KAFKA_BROKER: getEnv('KAFKA_BROKER', 'localhost:9092'),
  KAFKA_RETRY: getEnv('KAFKA_RETRY', '5', { transform: toNumber }),
  KAFKA_IDEMPOTENCY_ENABLE: getEnv('KAFKA_IDEMPOTENCY_ENABLE', 'true', {
    transform: toBool,
  }),
  KAFKA_IDEMPOTENCY_TTL: getEnv('KAFKA_IDEMPOTENCY_TTL', '86400', {
    transform: toNumber,
  }),

  GUEST_SIGNUP_PROVISION_TIMEOUT_MS: getEnv(
    'GUEST_SIGNUP_PROVISION_TIMEOUT_MS',
    '60000',
    { transform: toNumber },
  ),

  VALKEY_URL: getEnv('VALKEY_URL', 'valkey://localhost:6380'),
  VALKEY_PASSWORD: getEnv('VALKEY_PASSWORD', '', { required: true }),

  INTERNAL_GATEWAY_TOKEN: getEnv('INTERNAL_GATEWAY_TOKEN', '', {
    required: true,
  }),
  MAIL_TOKEN_CACHE_JWE_KEYS: getEnv('MAIL_TOKEN_CACHE_JWE_KEYS', '', {
    required: true,
  }),
  MAIL_TOKEN_CACHE_JWE_ACTIVE_KID: getEnv(
    'MAIL_TOKEN_CACHE_JWE_ACTIVE_KID',
    'v1',
  ),

  RATE_LIMIT_ENABLE: getEnv('RATE_LIMIT_ENABLE', 'true', { transform: toBool }),
  RATE_LIMIT_REQUESTS: getEnv('RATE_LIMIT_REQUEST', '100', {
    transform: toNumber,
  }),
  RATE_LIMIT_WINDOW: getEnv('RATE_LIMIT_WINDOW', '60000', {
    transform: toNumber,
  }),

  KC_CLIENT_SECRET: getEnv('KC_CLIENT_SECRET', '', { required: true }),
  KC_URL: keycloakIssuerUrl,
  KC_BACKCHANNEL_URL: getEnv('KC_BACKCHANNEL_URL', keycloakIssuerUrl),
  KC_REALM: getEnv('KC_REALM', 'camunda-platform'),
  KC_CLIENT_ID: getEnv('KC_CLIENT_ID', 'camunda-identity'),
  KC_AUTH_CLIENT_ID: getEnv('KC_AUTH_CLIENT_ID', '', { required: true }),
  KC_AUTH_CLIENT_SECRET: getEnv('KC_AUTH_CLIENT_SECRET', '', {
    required: true,
  }),
  KC_ADMIN_USERNAME: getEnv('KC_ADMIN_USERNAME', 'admin', { required: true }),
  KC_ADMIN_PASSWORD: getEnv('KC_ADMIN_PASSWORD', '', { required: true }),
  KC_TLS_REJECT_UNAUTHORIZED: getEnv('KC_TLS_REJECT_UNAUTHORIZED', 'true', {
    transform: toBool,
  }),

  COOKIE_SECRET: getEnv('COOKIE_SECRET', 'omnixys-development-secret', {
    required: true,
  }),
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

  DEFAULT_TENANT_ID: getEnv('DEFAULT_TENANT_ID', ''),

  TENANT_SERVICE_URL: getEnv('TENANT_SERVICE_URL', 'localhost:50052', {
    required: true,
  }),
  TENANT_GRPC_SERVICE_TOKEN: getEnv(
    'TENANT_GRPC_SERVICE_TOKEN',
    'dev-tenant-service-token',
    { required: true },
  ),
  TENANT_GRPC_AUTHENTICATION_TOKEN: getEnv(
    'TENANT_GRPC_AUTHENTICATION_TOKEN',
    'dev-authentication-service-token',
    { required: true },
  ),

  KEYCLOAK_HEALTH_URL: getEnv('KEYCLOAK_HEALTH_URL', ''),
  TEMPO_HEALTH_URL: getEnv('TEMPO_HEALTH_URL', ''),
  PROMETHEUS_HEALTH_URL: getEnv('PROMETHEUS_HEALTH_URL', ''),

  PC_JWE_KEY: getEnv('PC_JWE_KEY', '', { required: true }),
  PC_TTL_SEC: getEnv('PC_TTL_SEC', String(60 * 60 * 24 * 30), {
    transform: toNumber,
  }),

  DATABASE_URL: getEnv('DATABASE_URL', '', { required: true }),

  FRONTEND_URL: getEnv('FRONTEND_URL', '', { required: true }),

  GITHUB_CLIENT_ID: getEnv('GITHUB_CLIENT_ID', ''),
  GITHUB_REDIRECT_URI: getEnv('GITHUB_REDIRECT_URI', ''),
  GITHUB_CLIENT_SECRET: getEnv('GITHUB_CLIENT_SECRET', ''),
  GOOGLE_CLIENT_ID: getEnv('GOOGLE_CLIENT_ID', ''),
  GOOGLE_REDIRECT_URI: getEnv('GOOGLE_REDIRECT_URI', ''),
  GOOGLE_CLIENT_SECRET: getEnv('GOOGLE_CLIENT_SECRET', ''),

  WEBAUTHN_RP_ID: getEnv('WEBAUTHN_RP_ID', ''),
  WEBAUTHN_ORIGIN: getEnv('WEBAUTHN_ORIGIN', ''),
} as const;
