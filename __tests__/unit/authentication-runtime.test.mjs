import assert from 'node:assert/strict';
import test from 'node:test';
import 'reflect-metadata';

const { ContextAccessor } = await import('@omnixys/context-ts');
const { InvalidCredentialsException } = await import('@omnixys/security-ts');
const {
  AuthenticationStateException,
  AuthenticationInternalException,
} = await import(
  '../../dist/authentication/errors/authentication.error.js'
);
const { AuthWriteService } = await import(
  '../../dist/authentication/services/authentication-write.service.js'
);
const { AdminWriteService } = await import(
  '../../dist/authentication/services/admin-write.service.js'
);
const { keycloakTenantAttributes, resolveTenantId } = await import(
  '../../dist/authentication/utils/tenant-context.js'
);
const { UserWriteService } = await import(
  '../../dist/authentication/services/user-write.service.js'
);
const { RegisterService } = await import(
  '../../dist/authentication/services/register.service.js'
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

test('user deletion deletes Keycloak by K, local authUser by U, and fan-outs every downstream event', async () => {
  const sent = [];
  const deletedKc = [];
  const service = new AdminWriteService(
    logger,
    {},
    {},
    {},
    { send: async (event) => { sent.push(event); } },
    {
      authUser: {
        findUnique: async ({ where }) =>
          where.id === 'user-1' || where.keycloakSub === 'kc-1'
            ? { id: 'user-1', keycloakSub: 'kc-1' }
            : null,
        deleteMany: async ({ where }) => ({ count: where.id === 'user-1' ? 1 : 0 }),
      },
    },
  );
  service.kcRequest = async (method, path, _cfg, behavior) => {
    deletedKc.push({ method, path, behavior });
    return undefined;
  };

  await service.deleteUser('user-1', 'actor-1');

  // Keycloak deletion targets the external subject K (never U) and tolerates 404.
  assert.equal(deletedKc.length, 1);
  assert.equal(deletedKc[0].method, 'delete');
  assert.ok(deletedKc[0].path.endsWith(encodeURIComponent('kc-1')));
  assert.equal(deletedKc[0].behavior.ignoreNotFound, true);

  assert.equal(sent.length, 6);
  assert.deepEqual(new Set(sent.map(({ payload }) => payload.userId)), new Set(['user-1']));
  assert.ok(sent.every(({ meta }) => meta.actorId === 'actor-1'));
});

test('deleteUser accepts the Keycloak subject (K) and still propagates the internal U', async () => {
  const sent = [];
  const service = new AdminWriteService(
    logger,
    {},
    {},
    {},
    { send: async (event) => { sent.push(event); } },
    {
      authUser: {
        findUnique: async ({ where }) =>
          where.keycloakSub === 'kc-1' ? { id: 'user-1', keycloakSub: 'kc-1' } : null,
        deleteMany: async ({ where }) => ({ count: where.id === 'user-1' ? 1 : 0 }),
      },
    },
  );
  service.kcRequest = async () => undefined;

  await service.deleteUser('kc-1', 'actor-1');

  assert.equal(sent.length, 6);
  assert.deepEqual(new Set(sent.map(({ payload }) => payload.userId)), new Set(['user-1']));
});

test('deleteUser is an idempotent no-op when the authUser is already gone', async () => {
  let sent = 0;
  let kcCalls = 0;
  const service = new AdminWriteService(
    logger,
    {},
    {},
    {},
    { send: async () => { sent += 1; } },
    { authUser: { findUnique: async () => null, deleteMany: async () => ({ count: 0 }) } },
  );
  service.kcRequest = async () => { kcCalls += 1; };

  await service.deleteUser('missing-user', 'actor-1');

  assert.equal(sent, 0);
  assert.equal(kcCalls, 0);
});

test('isGuest resolves the GUEST role via Keycloak on the subject K', async () => {
  const service = new AdminWriteService(logger, {}, {}, {}, {}, {
    authUser: {
      findUnique: async ({ where }) =>
        where.id === 'user-1' ? { keycloakSub: 'kc-1' } : null,
    },
  });
  service.mapRoleInput = (role) => `${role}-realm`;
  service.kcRequest = async (_method, path) => {
    assert.ok(path.endsWith(`${encodeURIComponent('kc-1')}/role-mappings/realm`));
    return [{ name: 'GUEST-realm' }];
  };

  assert.equal(await service.isGuest('user-1'), true);
});

test('isGuest returns false for non-guests and for missing users without calling Keycloak', async () => {
  let kcCalls = 0;
  const service = new AdminWriteService(logger, {}, {}, {}, {}, {
    authUser: {
      findUnique: async ({ where }) =>
        where.id === 'user-1' ? { keycloakSub: 'kc-1' } : null,
    },
  });
  service.mapRoleInput = (role) => `${role}-realm`;
  service.kcRequest = async () => { kcCalls += 1; return [{ name: 'USER-realm' }]; };

  assert.equal(await service.isGuest('user-1'), false);
  assert.equal(await service.isGuest('missing-user'), false);
  assert.equal(kcCalls, 1);
});

test('isGuest treats a vanished Keycloak user (404) as a guest to keep cleanup idempotent', async () => {
  const service = new AdminWriteService(logger, {}, {}, {}, {}, {
    authUser: { findUnique: async () => ({ keycloakSub: 'kc-gone' }) },
  });
  service.kcRequest = async (_method, _path, _cfg, behavior) => {
    assert.equal(behavior.ignoreNotFound, true);
    return null;
  };

  assert.equal(await service.isGuest('user-1'), true);
});

test('tenant resolution prefers an explicit verified UUID and rejects invalid values', () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';

  assert.equal(resolveTenantId(tenantId), tenantId);
  assert.deepEqual(keycloakTenantAttributes(tenantId), { tenants: [tenantId] });
  assert.throws(
    () => resolveTenantId('not-a-uuid'),
    (error) =>
      error instanceof AuthenticationStateException &&
      error.code === 'AUTHENTICATION_STATE_INVALID',
  );
});

test('guest and OAuth Keycloak users receive tenant attributes', async () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';
  const requests = [];
  const membershipCalls = [];
  const service = new UserWriteService(
    logger,
    {},
    {},
    { async assignRealmRoleToUser() {}, async setOmnixysUidAttribute() {} },
    {},
    { async send() {} },
    {},
    {},
    { authUser: { async create() { return { id: '00000000-0000-4000-8000-000000000007' }; } } },
    { async schedule() {} },
    {},
    { async provisionMember(...args) { membershipCalls.push(args); } },
  );
  service.createUsernameAndEmailAndPassword = async () => ({
    username: 'ada',
    email: 'ada@example.com',
    password: 'secret',
  });
  service.findUserIdByUsername = async () => '00000000-0000-4000-8000-000000000006';
  service.adminJsonHeaders = async () => ({});
  service.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };

  await service.createGuestUser({
    firstName: 'Ada',
    lastName: 'Lovelace',
    eventEndsAt: new Date(Date.now() + 60_000),
    tenantId,
  });
  assert.deepEqual(requests[0].attributes, { tenants: [tenantId] });
  assert.deepEqual(membershipCalls, [[
    tenantId,
    '00000000-0000-4000-8000-000000000007',
    'GUEST',
  ]]);

  await ContextAccessor.run(
    {
      tenant: { tenantId, source: 'verified-principal', verified: true },
    },
    () =>
      service.createKeycloakUser({
        provider: 'github',
        providerId: 'provider-1',
        email: 'ada@example.com',
      }),
  );
  assert.deepEqual(requests[1].attributes.tenants, [tenantId]);
  assert.equal(requests[1].attributes.provider, 'github');
});

test('setOmnixysUidAttribute merges omnixys_uid while preserving existing attributes', async () => {
  const requests = [];
  const keycloakSub = 'keycloak-sub-guest';
  const uid = '01910000-0000-7000-8000-000000000001';
  const service = new AdminWriteService(logger, {}, {}, {}, {}, {});
  service.readService.findById = async () => ({
    id: keycloakSub,
    username: 'guest',
    firstName: 'Ada',
    lastName: 'Lovelace',
    email: 'ada@example.com',
    attributes: { tenants: ['00000000-0000-4000-8000-000000000005'] },
  });
  service.adminJsonHeaders = async () => ({});
  service.kcRequest = async (_method, _path, request) => {
    requests.push({ method: _method, path: _path, data: request.data });
  };

  await service.setOmnixysUidAttribute(keycloakSub, uid);

  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'put');
  assert.ok(requests[0].path.endsWith(encodeURIComponent(keycloakSub)));
  assert.equal(requests[0].data.attributes.omnixys_uid[0], uid);
  assert.deepEqual(requests[0].data.attributes.tenants, [
    '00000000-0000-4000-8000-000000000005',
  ]);
});

test('setOmnixysUidAttribute rethrows a failed projection as AuthenticationInternalException', async () => {
  const keycloakSub = 'keycloak-sub-failing';
  const uid = '01910000-0000-7000-8000-000000000002';
  const service = new AdminWriteService(logger, {}, {}, {}, {}, {});
  service.readService.findById = async () => ({
    id: keycloakSub,
    username: 'guest',
    firstName: 'Ada',
    lastName: 'Lovelace',
    email: 'ada@example.com',
    attributes: {},
  });
  service.adminJsonHeaders = async () => ({});
  service.kcRequest = async () => {
    throw new Error('keycloak put failed');
  };

  await assert.rejects(
    service.setOmnixysUidAttribute(keycloakSub, uid),
    (error) =>
      error instanceof AuthenticationInternalException &&
      error.code === 'AUTHENTICATION_INTERNAL_ERROR',
  );
});

test('standard and admin Keycloak sign-up receive tenant attributes', async () => {
  const tenantId = '00000000-0000-4000-8000-000000000005';
  const requests = [];
  const register = new RegisterService(
    logger,
    {},
    {},
    {},
    { async assignRealmRoleToUser() {} },
    {},
    {},
    {},
  );
  register.adminJsonHeaders = async () => ({});
  register.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };
  register.findUserIdByUsername = async () => undefined;

  const admin = new AdminWriteService(logger, {}, {}, {}, {}, {});
  admin.adminJsonHeaders = async () => ({});
  admin.kcRequest = async (_method, _path, request) => {
    requests.push(request.data);
  };
  admin.findUserIdByUsername = async () => undefined;

  await ContextAccessor.run(
    {
      tenant: { tenantId, source: 'verified-principal', verified: true },
    },
    async () => {
      await assert.rejects(
        register.signUp(
          {
            id: 'pending-user',
            username: 'ada',
            firstName: 'Ada',
            lastName: 'Lovelace',
            email: 'ada@example.com',
            password: 'secret',
          },
          'token',
        ),
      );
      await assert.rejects(
        admin.adminSignUp({
          username: 'admin',
          firstName: 'Admin',
          lastName: 'User',
          email: 'admin@example.com',
          password: 'secret',
        }),
      );
    },
  );

  assert.deepEqual(requests[0].attributes, { tenants: [tenantId] });
  assert.deepEqual(requests[1].attributes, { tenants: [tenantId] });
});
