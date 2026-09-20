import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ENV_MODULE = fileURLToPath(new URL('../../dist/config/env.js', import.meta.url));

const REQUIRED_ENV_KEYS = [
  'NODE_ENV',
  'VALKEY_URL',
  'VALKEY_PASSWORD',
  'KC_URL',
  'KC_REALM',
  'KC_CLIENT_ID',
  'KC_CLIENT_SECRET',
  'KC_ADMIN_USERNAME',
  'KC_ADMIN_PASSWORD',
  'COOKIE_SECRET',
  'ENCRYPTION_KEY',
  'DATABASE_URL',
  'DEFAULT_TENANT_ID',
  'KEYCLOAK_HEALTH_URL',
  'TEMPO_HEALTH_URL',
  'PROMETHEUS_HEALTH_URL',
  'OTEL_EXPORTER_OTLP_ENDPOINT',
  'OTEL_TRANSPORT_MODE',
  'TEMPO_URI',
  'KAFKA_BROKER',
];

function loadEnv(nodeEnv) {
  const env = { ...process.env };
  for (const key of REQUIRED_ENV_KEYS) {
    delete env[key];
  }
  if (nodeEnv !== undefined) {
    env.NODE_ENV = nodeEnv;
  }
  const program = `import(${JSON.stringify(ENV_MODULE)})
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error?.message ?? String(error));
      process.exit(1);
    });`;
  return spawnSync(process.execPath, ['--input-type=module', '-e', program], {
    cwd: tmpdir(),
    env,
    encoding: 'utf8',
  });
}

test('missing required env fails fast in development', () => {
  const { status, stderr } = loadEnv('development');
  assert.equal(status, 1);
  assert.match(stderr, /\[ENV\] Missing required env:/);
});

test('missing required env fails fast in staging', () => {
  const { status, stderr } = loadEnv('staging');
  assert.equal(status, 1);
  assert.match(stderr, /\[ENV\] Missing required env:/);
});

test('missing required env is tolerated in test and unset environments', () => {
  assert.equal(loadEnv('test').status, 0);
  assert.equal(loadEnv(undefined).status, 0);
});