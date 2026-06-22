# Authentication Service

The Authentication service owns identity verification and authentication workflows for Omnixys. It integrates Keycloak with password, refresh, OAuth, magic-link, TOTP, WebAuthn, backup-code, security-question, and password-reset flows.

It does not own user profile data, event membership, invitations, seats, tickets, notification delivery, request-context storage, log transport, or OpenTelemetry SDK lifecycle. Those responsibilities remain with their bounded services and the Omnixys framework packages.

## Runtime architecture

- NestJS 11 with Fastify and Apollo Federation 2
- Keycloak as the identity provider and token authority
- PostgreSQL through Prisma for MFA, device, OAuth-account, lockout, and reset state
- Valkey for ephemeral verification state, challenges, locks, and delayed jobs
- Kafka for identity lifecycle propagation
- `@omnixys/context` as the request, correlation, principal, tenant, and trace-metadata source
- `@omnixys/security` for guards, verified principals, hashing, encryption, rate limiting, and structured security exceptions
- `@omnixys/logger` and `@omnixys/observability` for correlated logs, spans, metrics, and graceful flushing
- `@omnixys/graphql` for schema generation and structured GraphQL error mapping
- `@omnixys/contracts` for cross-service DTOs, schemas, and error contracts

HTTP, GraphQL, and Kafka execution all enter the canonical context scope. Outgoing Kafka messages inherit `requestId`, `correlationId`, trace identifiers, actor, and tenant from that scope.

## Security boundaries

Public authentication operations include credentials login, sign-up verification, password reset initiation, OAuth callbacks, magic links, and passwordless challenges. Cookie/header guards protect authenticated account operations. All admin GraphQL mutations, identity lookup queries, and REST administration endpoints require the `ADMIN` realm role.

Credentials, access tokens, refresh tokens, magic-link tokens, reset tokens, backup codes, and WebAuthn responses must never be written to logs. Client-facing authentication failures use structured codes such as `INVALID_CREDENTIALS`, `REFRESH_TOKEN_EXPIRED`, `AUTHENTICATION_STATE_INVALID`, and `IDENTITY_PROVIDER_UNAVAILABLE`; the GraphQL mapper adds canonical request metadata.

## GraphQL API

The generated federation schema is written to `dist/schema.gql` by default. Set `SCHEMA_TARGET=tmp` for `/tmp/schema.gql` or `SCHEMA_TARGET=false` to disable file output.

The API exposes:

- credentials, refresh, logout, magic-link, and passwordless operations
- TOTP, WebAuthn, backup-code, and security-question management
- password-reset verification and completion
- guest and standard sign-up verification
- authenticated self-service profile/password mutations
- ADMIN-only identity lifecycle and role management

## Kafka flows

Consumers:

- `authentication.deleteGuest`
- `authentication.deleteGuestList`
- delayed `user.delete` jobs

Producers notify user, address, event, seat, invitation, ticket, and notification bounded contexts. Identity deletion awaits every downstream publication before reporting success. Package-level retry, DLQ, health, and shutdown behavior remain enabled through `KafkaModule`.

## Health and lifecycle

- `GET /health/liveness` checks the process.
- `GET /health/readiness` checks PostgreSQL, Kafka, and Valkey. Keycloak, Tempo, and Prometheus checks are included only when their health URLs are configured.
- Nest shutdown hooks close Prisma, Kafka, Valkey, logger, and observability resources.

## Configuration

Copy `.env.example` to `.env`. Production startup requires database, cookie, identity-provider, encryption, fingerprint, pending-contact, and HMAC secrets. Development fallbacks are not production credentials.

Key settings are `DATABASE_URL`, `KC_URL`, `KC_REALM`, `KC_CLIENT_ID`, `KC_CLIENT_SECRET`, `KAFKA_BROKER`, `VALKEY_URL`, `VALKEY_PASSWORD`, `TEMPO_URI`, `COOKIE_SECRET`, `PC_JWE_KEY`, `RESET_TOKEN_HMAC_SECRET`, `DEVICE_FINGERPRINT_HMAC_SECRET`, `MAGIC_LINK_HMAC_SECRET`, `ENCRYPTION_KEY`, and `FINGERPRINT_SECRET`.

## Development

```bash
pnpm install
pnpm generate
pnpm build
pnpm test:unit
pnpm test:integration
pnpm test:e2e
pnpm exec eslint src --max-warnings 0
pnpm pack --dry-run
```

E2E tests require Docker. They run sequentially because each suite owns an isolated PostgreSQL, Valkey, Kafka, Keycloak, and Tempo environment; every suite tears those resources down.

## Database changes

Validate and generate Prisma artifacts before committing schema changes:

```bash
pnpm exec prisma format
pnpm exec prisma validate
pnpm exec prisma generate
```

Apply migrations through the deployment pipeline. Do not use `prisma db push` against shared or production databases.
