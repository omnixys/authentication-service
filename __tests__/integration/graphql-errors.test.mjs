import assert from 'node:assert/strict';
import test from 'node:test';
import 'reflect-metadata';

const { ContextAccessor } = await import('@omnixys/context');
const { toGraphQLError } = await import('@omnixys/graphql');
const { InvalidCredentialsException, RefreshTokenExpiredException } = await import(
  '@omnixys/security'
);

test('GraphQL maps authentication failures with canonical request and trace metadata', () => {
  ContextAccessor.run(
    {
      requestId: 'request-graphql-1',
      correlationId: 'correlation-graphql-1',
      startedAtEpochMs: Date.now(),
      principal: { subject: 'subject-1', actorId: 'actor-1', roles: [] },
      tenant: { tenantId: 'tenant-1', source: 'verified-principal', verified: true },
      client: {},
      transport: { type: 'graphql', operation: 'credentialsLogin' },
      trace: { traceId: 'trace-graphql-1', spanId: 'span-graphql-1' },
    },
    () => {
      const mapped = toGraphQLError(new InvalidCredentialsException());
      assert.equal(mapped.extensions.code, 'INVALID_CREDENTIALS');
      assert.equal(mapped.extensions.requestId, 'request-graphql-1');
      assert.equal(mapped.extensions.correlationId, 'correlation-graphql-1');
      assert.equal(mapped.extensions.traceId, 'trace-graphql-1');
      assert.equal(mapped.extensions.actorId, 'actor-1');
      assert.equal(mapped.extensions.tenantId, 'tenant-1');
    },
  );
});

test('GraphQL preserves the refresh-token error contract', () => {
  const mapped = toGraphQLError(new RefreshTokenExpiredException());
  assert.equal(mapped.extensions.code, 'REFRESH_TOKEN_EXPIRED');
  assert.equal(mapped.message, 'Refresh token has expired');
  assert.deepEqual(mapped.extensions.metadata, {});
});
