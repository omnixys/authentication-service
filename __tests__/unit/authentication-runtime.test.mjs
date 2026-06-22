import assert from 'node:assert/strict';
import test from 'node:test';
import 'reflect-metadata';

const { ContextAccessor } = await import('@omnixys/context');
const { InvalidCredentialsException } = await import('@omnixys/security');
const { AuthenticationStateException } = await import(
  '../../dist/authentication/errors/authentication.error.js'
);
const { AuthWriteService } = await import(
  '../../dist/authentication/services/authentication-write.service.js'
);
const { AdminWriteService } = await import(
  '../../dist/authentication/services/admin-write.service.js'
);

const sink = { debug() {}, info() {}, warn() {}, error() {} };
const logger = { log: () => sink };

test('authentication errors retain canonical request metadata', () => {
  ContextAccessor.run(
    {
      requestId: 'request-auth-1',
      correlationId: 'correlation-auth-1',
      startedAtEpochMs: Date.now(),
      principal: { subject: 'subject-1', actorId: 'actor-1', roles: [] },
      tenant: { tenantId: 'tenant-1', source: 'verified-principal', verified: true },
      client: {},
      transport: { type: 'graphql', operation: 'credentialsLogin' },
      trace: { traceId: 'trace-auth-1', spanId: 'span-auth-1' },
    },
    () => {
      const error = new AuthenticationStateException('invalid-state');
      assert.equal(error.code, 'AUTHENTICATION_STATE_INVALID');
      assert.equal(error.requestId, 'request-auth-1');
      assert.equal(error.correlationId, 'correlation-auth-1');
      assert.equal(error.traceId, 'trace-auth-1');
      assert.equal(error.actorId, 'actor-1');
      assert.equal(error.tenantId, 'tenant-1');
    },
  );
});

test('unknown usernames are mapped to InvalidCredentials without leaking existence', async () => {
  let dummyVerifications = 0;
  const service = new AuthWriteService(
    logger,
    {},
    {},
    {},
    {},
    {},
    {},
    {},
    { findByUsername: async () => { throw new Error('not found'); } },
    {},
    { dummyVerify: async () => { dummyVerifications += 1; } },
    {},
  );

  await assert.rejects(
    service.passwordLogin({ username: 'missing', password: 'secret' }),
    (error) => error instanceof InvalidCredentialsException && error.code === 'INVALID_CREDENTIALS',
  );
  assert.equal(dummyVerifications, 1);
});

test('user deletion awaits every downstream event and uses idempotent local deletion', async () => {
  const sent = [];
  const service = new AdminWriteService(
    logger,
    {},
    {},
    {},
    { send: async (event) => { sent.push(event); } },
    { authUser: { deleteMany: async ({ where }) => ({ count: where.id === 'user-1' ? 1 : 0 }) } },
  );
  service.kcRequest = async () => undefined;

  await service.deleteUser('user-1', 'actor-1');

  assert.equal(sent.length, 6);
  assert.deepEqual(new Set(sent.map(({ payload }) => payload.userId)), new Set(['user-1']));
  assert.ok(sent.every(({ meta }) => meta.actorId === 'actor-1'));
});
