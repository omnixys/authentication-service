import 'reflect-metadata';

process.env.GUEST_SIGNUP_PROVISION_TIMEOUT_MS = '120';

const { UserWriteService } = await import(
  '../../dist/authentication/services/user-write.service.js'
);
const { GuestSignupException } = await import(
  '../../dist/authentication/errors/authentication.error.js'
);
const { ContextAccessor } = await import('@omnixys/context-ts');
const { KafkaTopics } = await import('@omnixys/kafka-ts');
import assert from 'node:assert/strict';
import test from 'node:test';

const sink = { debug() {}, info() {}, warn() {}, error() {} };
const logger = { log: () => sink };

const TENANT_ID = '00000000-0000-4000-8000-000000000005';
const USER_ID = '00000000-0000-4000-8000-000000000007';
const KEYCLOAK_SUB = '00000000-0000-4000-8000-000000000006';
const INVITATION_ID = '00000000-0000-4000-8000-000000000008';
const AUTH_KEY = 'guest-key';

function guestPayload(overrides = {}) {
  return JSON.stringify({
    actorId: '00000000-0000-4000-8000-000000000009',
    tenantId: TENANT_ID,
    invitees: [
      {
        invitationId: INVITATION_ID,
        email: 'ada@example.com',
        firstName: 'Ada',
        lastName: 'Lovelace',
        ...overrides,
      },
    ],
    eventEndsAt: new Date(Date.now() + 60_000).toISOString(),
  });
}

function buildService({ marker = '1', markers, onCreateUser }) {
  const requests = [];
  const sent = [];
  const sharedKeys = [];
  let deletedKey = null;

  const service = new UserWriteService(
    logger,
    {},
    {},
    {
      async assignRealmRoleToUser() {},
      async setOmnixysUidAttribute() {},
    },
    {},
    { send: async (event) => sent.push(event) },
    {
      decrypt() {
        return JSON.stringify({
          authKey: AUTH_KEY,
          userKey: 'user-key',
          eventKey: 'event-key',
          seatKey: 'seat-key',
        });
      },
    },
    {
      async get() {
        return guestPayload();
      },
      async getShared(key) {
        sharedKeys.push(key);
        if (markers) {
          return markers.length > 1 ? markers.shift() : markers[0];
        }
        return marker;
      },
      async delete(key, authKey) {
        deletedKey = { key, authKey };
      },
    },
    {
      authUser: {
        async create() {
          onCreateUser?.();
          return { id: USER_ID, keycloakSub: KEYCLOAK_SUB };
        },
        async deleteMany({ where }) {
          return { count: where.id === USER_ID ? 1 : 0 };
        },
      },
    },
    { async schedule() {} },
    {},
    { async provisionMember() {} },
  );

  service.createUsernameAndEmailAndPassword = async () => ({
    username: 'guest_ada',
    email: 'ada@example.com',
    password: 'secret',
  });
  service.findUserIdByUsername = async () => KEYCLOAK_SUB;
  service.adminJsonHeaders = async () => ({});
  service.kcRequest = async (method, path, body) => {
    requests.push({ method, path, body });
  };

  return {
    service,
    requests,
    sent,
    getDeletedKey: () => deletedKey,
    getSharedKeys: () => sharedKeys,
  };
}

test('guest sign-up waits for the completion marker and enrolls the guest', async () => {
  const { service, sent, getDeletedKey, getSharedKeys } = buildService({
    marker: '1',
  });
  let created = 0;
  const s = service;
  // eslint-disable-next-line require-await
  const originalCreate = s.createGuestUser.bind(s);
  const delegation = service.createGuestUser.bind(service);
  service.createGuestUser = async (data) => {
    created += 1;
    return delegation(data);
  };
  void originalCreate;

  const result = await ContextAccessor.run(
    { requestId: 'request-signup-ok', tenantId: TENANT_ID },
    () => service.guestSignUp('encrypted-token', {}),
  );

  assert.equal(created, 1);
  assert.equal(result.users.length, 1);
  assert.equal(result.users[0].userId, USER_ID);

  const topics = sent.map((event) => event.topic);
  assert.deepEqual(new Set(topics), new Set([
    KafkaTopics.user.createGuest,
    KafkaTopics.event.addRole,
    KafkaTopics.seat.addGuestId,
  ]));
  const createGuest = sent.find((event) => event.topic === KafkaTopics.user.createGuest);
  assert.equal(createGuest.payload.invitationId, INVITATION_ID);
  assert.equal(createGuest.payload.userId, USER_ID);

  const deleted = getDeletedKey();
  assert.ok(deleted, 'verification token must be consumed after a successful sign-up');
  assert.equal(deleted.authKey, AUTH_KEY);

  assert.equal(
    getSharedKeys()[0],
    `guest-signup:${INVITATION_ID}:${USER_ID}`,
    'the completion marker must be read from the shared, service-agnostic namespace',
  );

  assert.equal(
    getDeletedKey().authKey,
    AUTH_KEY,
    'the guest verification payload must be deleted once',
  );
});

test('guest sign-up fails closed and compensates when the chain does not complete', async () => {
  const { service, requests, sent, getDeletedKey } = buildService({ marker: null });

  await assert.rejects(
    ContextAccessor.run(
      { requestId: 'request-signup-timeout', tenantId: TENANT_ID },
      () => service.guestSignUp('encrypted-token', {}),
    ),
    (error) =>
      error instanceof GuestSignupException &&
      error.code === 'GUEST_SIGNUP_FAILED' &&
      error.diagnostics?.reason === 'provisioning-incomplete',
  );

  const created = requests.filter((request) => request.method === 'post');
  const deleted = requests.filter((request) => request.method === 'delete');
  assert.equal(created.length, 1);
  assert.equal(deleted.length, 1, 'the created Keycloak user must be rolled back');
  assert.ok(deleted[0].path.endsWith(encodeURIComponent(KEYCLOAK_SUB)));

  const topics = sent.map((event) => event.topic);
  for (const topic of [
    KafkaTopics.user.deleteUser,
    KafkaTopics.event.delete,
    KafkaTopics.seat.removeGuestId,
    KafkaTopics.invitation.deleteUserInvitations,
    KafkaTopics.ticket.deleteUserTickets,
  ]) {
    assert.ok(topics.includes(topic), `expected compensation topic ${topic}`);
  }
  assert.ok(
    sent.every((event) =>
      event.topic === KafkaTopics.user.createGuest ||
      event.topic === KafkaTopics.event.addRole ||
      event.topic === KafkaTopics.seat.addGuestId ||
      event.payload?.userId === USER_ID,
    ),
    'every downstream cleanup targets the rolled-back guest',
  );

  assert.equal(
    getDeletedKey(),
    null,
    'the verification token must NOT be consumed after a failed sign-up',
  );
});

test('guest sign-up accepts a marker committed during the final compensation check', async () => {
  const { service, requests, getDeletedKey } = buildService({
    // The provisioner misses its polling deadline, then the invitation marker
    // becomes visible immediately before compensation begins.
    markers: [null, null, '1'],
  });

  const result = await ContextAccessor.run(
    { requestId: 'request-signup-final-marker', tenantId: TENANT_ID },
    () => service.guestSignUp('encrypted-token', {}),
  );

  assert.equal(result.users.length, 1);
  assert.equal(
    requests.filter((request) => request.method === 'delete').length,
    0,
    'a guest completed during the final check must not be compensated',
  );
  assert.ok(getDeletedKey(), 'the verification token is consumed on success');
});
