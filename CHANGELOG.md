# 🧾 Changelog

All notable changes in this project will be documented in this file.


## [4.1.1](https://github.com/omnixys/authentication-service/compare/v4.1.0...v4.1.1) (2026-09-13)

### Deps

* **Deps:** update omnixys packages ([](https://github.com/omnixys/authentication-service/commit/0b7038e72de9c2512e1cf85776850e918f5c2efd))

## [4.1.0](https://github.com/omnixys/authentication-service/compare/v4.0.2...v4.1.0) (2026-09-13)

### Auth

* **Auth:** fail closed when guest provisioning is incomplete ([](https://github.com/omnixys/authentication-service/commit/346aa3052c41d1b5b16d99cea74afdc8962623d6))
* **Auth:** expose guest signup reason in public error metadata ([](https://github.com/omnixys/authentication-service/commit/8afb90b9290ccdd839bd964f4f28dc3f3afa91ee))
* **Auth:** read guest signup marker from service-agnostic cache key ([](https://github.com/omnixys/authentication-service/commit/c28cf7cfce5ebf886e02b2ebfad94e52b5415eed))

## [4.0.2](https://github.com/omnixys/authentication-service/compare/v4.0.1...v4.0.2) (2026-09-11)

### Deps

* **Deps:** update omnixys contracts-ts package ([](https://github.com/omnixys/authentication-service/commit/8277ff2c60f09d9819efc9cc88c58ea7e9e46256))

## [4.0.1](https://github.com/omnixys/authentication-service/compare/v4.0.0...v4.0.1) (2026-09-10)

### Deps

* **Deps:** update graphql-ts ([](https://github.com/omnixys/authentication-service/commit/2a86a78c63af20ffaf94fd4f982a45f7fa0ca184))

## [4.0.0](https://github.com/omnixys/authentication-service/compare/v3.5.1...v4.0.0) (2026-09-05)

### Auth

* **Auth:** persist omnixys_uid projection on admin sign-up and surface Keycloak write failures ([](https://github.com/omnixys/authentication-service/commit/e3247811f1ab50c75e31beb86b80d446907366ba))

### Authentication

* **Authentication:** provision guest tenant memberships ([](https://github.com/omnixys/authentication-service/commit/961b35a4ece7fb4379e2dcc7e2ac56ef5567b290))
* **Authentication:** provision tenant membership on registration ([](https://github.com/omnixys/authentication-service/commit/3cd0aca76638a9c978de4e5be1ef146b7dd5256f))

### Deps

* **Deps:** update omnixys deps ([](https://github.com/omnixys/authentication-service/commit/f65c7e2aa2bce56840c49e35ea71a16f922b294d))
* **Deps:** use local contracts dependency for identity work ([](https://github.com/omnixys/authentication-service/commit/be79196f0ce01e682fb78ea65500c071398196d3))

### Docker

* **Docker:** align service runtime image to node 26 and pnpm 11 ([](https://github.com/omnixys/authentication-service/commit/50587c3baab9a3cdea343563a0302cbfcb8beb8e))

### Identity

* **Identity:** document final U/K identity semantics ([](https://github.com/omnixys/authentication-service/commit/8d69b109e9d89f69b647ca916731ccb7efa3271d))
* **Identity:** document transitional identity model and toolchain ([](https://github.com/omnixys/authentication-service/commit/01407b7e9252c097bb3828e62f7dbc9097c8bd45))
* **Identity:** add nullable keycloak subject and drop unused id default ([](https://github.com/omnixys/authentication-service/commit/28e768e0e3ee4e2e4e5dcf1c45d1e4b9a243dac8))
* **Identity:** project omnixys_uid to keycloak before token issuance ([](https://github.com/omnixys/authentication-service/commit/631bb8ebec7f826e84423a826043512d8a310ed8))
* **Identity:** provision auth users with uuid v7 identities ([](https://github.com/omnixys/authentication-service/commit/25bd989468570160ced9e9895f925fb7c15e2f0d))
* **Identity:** resolve K-as-U in login flows, fix naming (keycloakSub for K), align createPasswordlessSession U/K ([](https://github.com/omnixys/authentication-service/commit/9b517edb71a29ecafe0e88b5e432c16ea876ad8b))

### Lint

* **Lint:** fix lint errors ([](https://github.com/omnixys/authentication-service/commit/75499f09da2676e09970df16a882860b3b3d4bcd))

### Logging

* **Logging:** add service:authentication provenance source to logger acquisitions ([](https://github.com/omnixys/authentication-service/commit/0f81dd6b35a4f6e268709c99c171d08e0138f15f))
* **Logging:** add missing format placeholders to structured log calls ([](https://github.com/omnixys/authentication-service/commit/3bdfa3e132f6c2264a2ef4a9bf094f3a688d5842))

### Other

* **Other:** Merge pull request #23 from omnixys/migration/uuid-v7 ([](https://github.com/omnixys/authentication-service/commit/8bdef6b7fc20212ec970043af79d13ca6d30f337)), closes [#23](https://github.com/omnixys/authentication-service/issues/23)

### Prisma

* **Prisma:** update schema ([](https://github.com/omnixys/authentication-service/commit/e46377f2d91f758557454b7c21500c4dcdf1394a))

### Runtime

* **Runtime:** align github actions toolchain and label mapping ([](https://github.com/omnixys/authentication-service/commit/396184719839930a12e1d0ce7d0bdd7158c77d91))
* **Runtime:** align service runtime with node 26 and pnpm 11 ([](https://github.com/omnixys/authentication-service/commit/aa372eff94dc6b31d8acb17fb7817ae78f8ad7d6))

## [3.5.1](https://github.com/omnixys/authentication-service/compare/v3.5.0...v3.5.1) (2026-08-31)

### Kc

* **Kc:** add backchannel ([](https://github.com/omnixys/authentication-service/commit/20649cf07c405c5302ea5c774fbfa687ff4ccb76))

### Mail

* **Mail:** document local token exchange env ([](https://github.com/omnixys/authentication-service/commit/14cd632da51b037e1aa14923664526910f09ff02))

## [3.5.0](https://github.com/omnixys/authentication-service/compare/v3.4.5...v3.5.0) (2026-08-30)

### Mail

* **Mail:** add downscoped Stalwart token exchange ([](https://github.com/omnixys/authentication-service/commit/8059d17856fc1bd7f98b3b3824e9eaf8d3041e2f))

## [3.4.5](https://github.com/omnixys/authentication-service/compare/v3.4.4...v3.4.5) (2026-08-28)

### Deps

* **Deps:** update contracts-ts ([](https://github.com/omnixys/authentication-service/commit/d2b81c33178b7952273b7b557e64c63762715a77))

### Tenants

* **Tenants:** assign tenant claims to created users ([](https://github.com/omnixys/authentication-service/commit/7330c194a2a1e66745af4c5842fd7ea32d250d07))

## [3.4.4](https://github.com/omnixys/authentication-service/compare/v3.4.3...v3.4.4) (2026-08-26)

### Build

* **Build:** fix build errors ([](https://github.com/omnixys/authentication-service/commit/decf812c7719f43bbc1d1da013ad34967f87b27a))

## [3.4.3](https://github.com/omnixys/authentication-service/compare/v3.4.2...v3.4.3) (2026-08-26)

### Build

* **Build:** fix build errors ([](https://github.com/omnixys/authentication-service/commit/f2244709012d47a4a7f4f6a791c892b3a0802d38))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/561d122fb36598884714ce112be2f74b9de2c469))

## [3.4.2](https://github.com/omnixys/authentication-service/compare/v3.4.1...v3.4.2) (2026-08-26)

### Build

* **Build:** fix build errors ([](https://github.com/omnixys/authentication-service/commit/78e6969c691560bece0dc1fd0fb260d1558e7051))

## [3.4.1](https://github.com/omnixys/authentication-service/compare/v3.4.0...v3.4.1) (2026-08-26)

### Deps

* **Deps:** update logger to 3.2.6 ([](https://github.com/omnixys/authentication-service/commit/f8a529aa97ec9f0a2554b4c6d5fb6915673c63d6))
* **Deps:** update shared TypeScript packages ([](https://github.com/omnixys/authentication-service/commit/f5a28cf1a1feb51b94faa95cfe77c99d9f12d129))

## [3.4.0](https://github.com/omnixys/authentication-service/compare/v3.3.5...v3.4.0) (2026-08-26)

### Deps

* **Deps:** update omnixys ts packages ([](https://github.com/omnixys/authentication-service/commit/7313fb202a108d0f9ebc8f4680d7bc9ab1b55fb5))

### Otel

* **Otel:** add otel logs ([](https://github.com/omnixys/authentication-service/commit/98ae255cb239dc3d9d99d21e42732cff755d5bb5))

## [3.3.5](https://github.com/omnixys/authentication-service/compare/v3.3.4...v3.3.5) (2026-08-23)

### Auth

* **Auth:** remove credential debug logging ([](https://github.com/omnixys/authentication-service/commit/6dd7a121978346a18fe3a31cb7d1849095740f20))

### Logger

* **Logger:** fix terminal logger ([](https://github.com/omnixys/authentication-service/commit/60d9074ffe8c7b7c49c84bcda57751a735f868c4))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/a4c8cacfc46389634d455ad8a6fa1b435caa8907))

## [3.3.4](https://github.com/omnixys/authentication-service/compare/v3.3.3...v3.3.4) (2026-08-23)

### Logger

* **Logger:** update logger deps ([](https://github.com/omnixys/authentication-service/commit/c1cc7ac237a6168102a9c6c40409164de2cbbe07))

## [3.3.3](https://github.com/omnixys/authentication-service/compare/v3.3.2...v3.3.3) (2026-08-23)

### Error

* **Error:** update error handling ([](https://github.com/omnixys/authentication-service/commit/bdac4ddebf5f1ec064eb8ed60cdb547bb92b9cf4))

## [3.3.2](https://github.com/omnixys/authentication-service/compare/v3.3.1...v3.3.2) (2026-08-23)

### Observability

* **Observability:** update ([](https://github.com/omnixys/authentication-service/commit/8298460addde03c505d0dedc8e6f8b04c166e79d))
* **Observability:** update dependency ([](https://github.com/omnixys/authentication-service/commit/2328ba5f22c08c9d8efc01b1a730c697fc614371))

## [3.3.1](https://github.com/omnixys/authentication-service/compare/v3.3.0...v3.3.1) (2026-08-19)

### Agent

* **Agent:** add repository development instructions ([](https://github.com/omnixys/authentication-service/commit/7a577013b5162308ea41753dd5b705a7aee64875))

### Authentication

* **Authentication:** exclude health endpoints from rate-limit and bump version ([](https://github.com/omnixys/authentication-service/commit/9444eeb6e06b2fb39f107448282e3e106a885215))

### Rate-limit

* **Rate-limit:** replace deprecated skip with allowList for @fastify/rate-limit v10 ([](https://github.com/omnixys/authentication-service/commit/b1cc02148149f8f54b40e82258de3d59f075d4ce))

## [3.3.0](https://github.com/omnixys/authentication-service/compare/v3.2.0...v3.3.0) (2026-08-03)

### Analytics

* **Analytics:** publish authentication facts via outbox ([](https://github.com/omnixys/authentication-service/commit/3e34625341b8c7435f81457c1693107046484585))

### Config

* **Config:** require and validate DEFAULT_TENANT_ID ([](https://github.com/omnixys/authentication-service/commit/2c0fd8d7f5cd80af80928d2d50fd2b43e8fd2b72))
* **Config:** support trusted proxy address policy ([](https://github.com/omnixys/authentication-service/commit/e286af752ef1006ea0286b8389b992b690c13506))

### Keycloak

* **Keycloak:** declare tenants user-profile attribute in fixture ([](https://github.com/omnixys/authentication-service/commit/b8c9f595f0eca9ffae5063a74d507f7c881f5103))
* **Keycloak:** map identity provider failures safely ([](https://github.com/omnixys/authentication-service/commit/038a14fd87aeda6f97d7b33952ab2ee993a7fd36))
* **Keycloak:** drop unsupported userProfile field from test fixture ([](https://github.com/omnixys/authentication-service/commit/58ca9f8f3fcd419a3d9ad614979160cb7f8a55f1))

### Platform-token

* **Platform-token:** mint RS256 platform tokens with tenant claims and KC mirror ([](https://github.com/omnixys/authentication-service/commit/2bc81a8d4592be762ccea85efdd540100353d1dd))

### Tenant

* **Tenant:** wire tenant verification and drop default-tenant mode ([](https://github.com/omnixys/authentication-service/commit/388420ca837c828f2d9094945158e90d0ce3f1f7))
* **Tenant:** use DEFAULT_TENANT_ID instead of hardcoded 'omnixys' ([](https://github.com/omnixys/authentication-service/commit/81142bce45e45e6d1cfc42ddc3d7ef49e6ccc1d4))

## [3.2.0](https://github.com/omnixys/authentication-service/compare/v3.1.0...v3.2.0) (2026-07-28)

### Auth

* **Auth:** add structured logging to MFA, lockout, TOTP, backup codes, security questions, pending contacts, OAuth, and WebAuthn ([](https://github.com/omnixys/authentication-service/commit/2218dc7a147e09c29e42d2f62877c0331c460a84))

### Authentication

* **Authentication:** add structured logging to keycloak getAdminToken and OAuth fetch calls ([](https://github.com/omnixys/authentication-service/commit/a3a0d184edbed5e3d7453400877121d57617e737))

### Logging

* **Logging:** resolve build and lint errors in structured logger calls ([](https://github.com/omnixys/authentication-service/commit/451935724f9bce5788d70efd02328856f2c807a0))

### Prisma

* **Prisma:** add generated prisma files ([](https://github.com/omnixys/authentication-service/commit/8837f5a4ca26f3ece79e013694c190b0503da05e))
* **Prisma:** add generated prisma files ([](https://github.com/omnixys/authentication-service/commit/bb2c135c5c0e4962465905e0e49b98f360873f0a))
* **Prisma:** add generated prisma files ([](https://github.com/omnixys/authentication-service/commit/dc32cadb11b4e4a68aa11837c7f93efa3a230d6b))
* **Prisma:** remove generated prisma files ([](https://github.com/omnixys/authentication-service/commit/e4718cea1554e3bfa0cdec635c193f3a08af2648))

## [3.1.0](https://github.com/omnixys/authentication-service/compare/v3.0.0...v3.1.0) (2026-07-24)

### Deps

* **Deps:** remove obsolete/redundant dependencies ([](https://github.com/omnixys/authentication-service/commit/26ef0d432fc1772a638b790cbcef422a1be53515))

### Log

* **Log:** remove logstream dep ([](https://github.com/omnixys/authentication-service/commit/7378fccfc2174c9454e5fc9875088e6c9e73a6f2))

### Logger

* **Logger:** remove Kafka log transport config ([](https://github.com/omnixys/authentication-service/commit/6942ec38d7209654b80fc3f2763a87e9c6722369))

### Other

* **Other:** chore:(package.json): Update package.json ([](https://github.com/omnixys/authentication-service/commit/cb5745d6c55c3f06d7422319bc0d48a855cb6f07))

## [3.0.0](https://github.com/omnixys/authentication-service/compare/v2.1.0...v3.0.0) (2026-07-16)

### New

* **New:** new service ([](https://github.com/omnixys/authentication-service/commit/cec3920b0abb815646a364cc88ab3a1c876c61ae))

## [2.1.0](https://github.com/omnixys/authentication-service/compare/v2.0.2...v2.1.0) (2026-07-02)

### Deps

* **Deps:** update dependencys ([](https://github.com/omnixys/authentication-service/commit/cfc8482a683a54b245680c288cd33de5603ec40f))

## [2.0.2](https://github.com/omnixys/authentication-service/compare/v2.0.1...v2.0.2) (2026-06-29)

### Kafka

* **Kafka:** update kafka dependency ([](https://github.com/omnixys/authentication-service/commit/854cdcd154a7df1546ea4d9beaf309614d089ddf))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/51733eca2b238c0d6f53a1af89bbb970582bdfb2))

## [2.0.1](https://github.com/omnixys/authentication-service/compare/v2.0.0...v2.0.1) (2026-06-28)

### Dependencies

* **Dependencies:** update Dependecies ([](https://github.com/omnixys/authentication-service/commit/5f2583b1dbc59e22670d3ef3f4b30157048468bf))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cd6802a05649c0f1a4223f19b510ccca07f73d46))

## [2.0.0](https://github.com/omnixys/authentication-service/compare/v1.0.5...v2.0.0) (2026-06-28)

### Authentication

* **Authentication:** harden identity context and lifecycle ([](https://github.com/omnixys/authentication-service/commit/5fa74da7a0b23616d0d6c38537f3ea68f50fbeb9))

### Dependencies

* **Dependencies:** update Dependecies ([](https://github.com/omnixys/authentication-service/commit/12ffaa7f75044e3ddef217f9a0f908d61525833f))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/975d7e939ada8466a96f50e07dcf5c87c0005fbe))

## [1.0.5](https://github.com/omnixys/authentication-service/compare/v1.0.4...v1.0.5) (2026-05-25)

### Docker

* **Docker:** Dockerfile ([](https://github.com/omnixys/authentication-service/commit/e84735a03d11e7834c42c3d580aba71fb95e87c8))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/75c20f1fd5aa5a8faa95feb6b206b3964c90f785))

## [1.0.4](https://github.com/omnixys/authentication-service/compare/v1.0.3...v1.0.4) (2026-05-24)

### Dockerfile

* **Dockerfile:** build ([](https://github.com/omnixys/authentication-service/commit/7a8bc43661fcc561ea92fa6b50014a95350786ee))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/217743d4f4d1bcad0e2da75d3ff47223712450cd))

## [1.0.3](https://github.com/omnixys/authentication-service/compare/v1.0.2...v1.0.3) (2026-05-24)

### Docker

* **Docker:** build ([](https://github.com/omnixys/authentication-service/commit/65900b4d9900d7a4a859ca57556ea2eec88bb711))

## [1.0.2](https://github.com/omnixys/authentication-service/compare/v1.0.1...v1.0.2) (2026-05-24)

### Docker

* **Docker:** build ([](https://github.com/omnixys/authentication-service/commit/ce340e35371f1780e006dc6e5cce1c7a4306514e))

### Other

* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/876613ac191a530caba5bef3e3218bf4d4fedd95))

## [1.0.1](https://github.com/omnixys/authentication-service/compare/v1.0.0...v1.0.1) (2026-05-24)

### Docker

* **Docker:** build ([](https://github.com/omnixys/authentication-service/commit/49339204002b84ea570334b9c6fb9929698a5823))

### Prisma

* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/bcb0d6524e556f6a8ded4eaa92328ea685ffb0f5))

## 1.0.0 (2026-05-01)

### ⚠ BREAKING CHANGE

* **Fix:** authentication lint handling now validates missing step-up methods explicitly and wraps caught errors with causes.

### Adapter

* **Adapter:** Upgrade dependencies and add Valkey adapter ([](https://github.com/omnixys/authentication-service/commit/9132d62afc9b6e4e330354cfecbd29c3efdf6a96))

### Auth

* **Auth:** add admin-secured meByToken query and improve user-role handling ([](https://github.com/omnixys/authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
* **Auth:** add totp ([](https://github.com/omnixys/authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
* **Auth:** add webauthn ([](https://github.com/omnixys/authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
* **Auth:** implement GraphQL models and DTOs for User, Role, Permission ([](https://github.com/omnixys/authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))

### Auth-service

* **Auth-service:** configure OpenTelemetry service_name and unify metrics labels ([](https://github.com/omnixys/authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))

### Authentication

* **Authentication:** Add Valkey rate-limit adapter & pass client context ([](https://github.com/omnixys/authentication-service/commit/61365c83295782cdfea6072de6a1cf422c5f98c5))
* **Authentication:** authentication service v4.0.0 ([](https://github.com/omnixys/authentication-service/commit/9462025b890c077bd3e4f0423b4a16c1935c9b2f))

### Ci

* **Ci:** add release, multi-arch build/push & deploy ([](https://github.com/omnixys/authentication-service/commit/3555589f7cb9b5e588b797568009433259540b51))
* **Ci:** change secret.SERVICE to var.SERVICE ([](https://github.com/omnixys/authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
* **Ci:** add ci/cd workflow ([](https://github.com/omnixys/authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/a34249e609cb241f769588cbc7573bbfce8c8c0e))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/f07f500246d223395dff2d08b2b14a38c27e90c0))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/52717ec1558e582f029c023f5982c897f61337c5))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/d0594f7531087d73bf91b51687ffc086a66d053b))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/11cdc0ecd442d9165b23d8264861e9abb89f8131))
* **Ci:** update CI ([](https://github.com/omnixys/authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))

### Deploy

* **Deploy:** fix deploy.yml ([](https://github.com/omnixys/authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
* **Deploy:** test deploy.yml ([](https://github.com/omnixys/authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))

### Docker

* **Docker:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))

### Dockerfile

* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))

### Fix

* **Fix:** resolve authentication lint violations ([](https://github.com/omnixys/authentication-service/commit/90bfd702fbab24ca7546d8723b72bc524f3b2a2f))

### Graphql

* **Graphql:**  setup graphQL module with code-first schema generation ([](https://github.com/omnixys/authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))

### Husky

* **Husky:** add husky semantic ([](https://github.com/omnixys/authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
* **Husky:** update husky ([](https://github.com/omnixys/authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

### Mfa

* **Mfa:** add mfa ([](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))

### Other

* **Other:** workflow completed ([](https://github.com/omnixys/authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
* **Other:** 1.0.0 ([](https://github.com/omnixys/authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
* **Other:** add .github folder ([](https://github.com/omnixys/authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
* **Other:** add ci ([](https://github.com/omnixys/authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
* **Other:** add security Notification ([](https://github.com/omnixys/authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
* **Other:** Create deploy.yml ([](https://github.com/omnixys/authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
* **Other:** Create docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
* **Other:** init nest Project ([](https://github.com/omnixys/authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/df775ffe8c5ab413fa7331a094920a9a5fbf0cb9))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4fba9b6d3805a0ab2d5ae72d7bc8aeab79d99ef3))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/93f27f97e4af68aa9cae8b0de02ac7dcad78734f))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
* **Other:** Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([](https://github.com/omnixys/authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/authentication-service/issues/10)
* **Other:** Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/authentication-service/issues/14)
* **Other:** Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/authentication-service/issues/15)
* **Other:** Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([](https://github.com/omnixys/authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/authentication-service/issues/8)
* **Other:** Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([](https://github.com/omnixys/authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/authentication-service/issues/9)
* **Other:** Remove e2e tests; add workflow copies ([](https://github.com/omnixys/authentication-service/commit/cbd5ebf69fa9661229e4caf63f31aa675a861685))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
* **Other:** update ci ([](https://github.com/omnixys/authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
* **Other:** update CI ([](https://github.com/omnixys/authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
* **Other:** Update cors.ts ([](https://github.com/omnixys/authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
* **Other:** Update package.json ([](https://github.com/omnixys/authentication-service/commit/68b022f308f3360c820d81fed368cbc5e5f238f9))
* **Other:** Update task.yml ([](https://github.com/omnixys/authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
* **Other:** update workflow ([](https://github.com/omnixys/authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))

### Package

* **Package:** intergrated @omnixys/kafka package ([](https://github.com/omnixys/authentication-service/commit/14b7cf5eb1f97799dec2aa61f6c445997e1fe245))
* **Package:** add omnixys packages ([](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

### Prisma

* **Prisma:** add MFA ([](https://github.com/omnixys/authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
* **Prisma:** add Security Question ([](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))

### Register

* **Register:** add register flow ([](https://github.com/omnixys/authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

### Release

* **Release:** v1.0.0 ([](https://github.com/omnixys/authentication-service/commit/e29e19f9f8cdce8370fbef8c6e08c2fa8297b942))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a3c661f7535a05fb4a752b46739845273dded962))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/d751b5742c0cec8e5536b517e07f0b195ecedab5))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/586a1d23c71f0ccb7b0a428b4eaf6bd4e47562b2))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/95c5b80dcddaf488b5216ab5f8e5031e823f4be9))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/9ab94c422fc4cd801eb45bbcab1f6119fc8bf621))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/94be53309cd132b831b949cf0dd7ef9a2043de03))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/ff3bc0ace98b005829c4dbedb27310974597aeec))
* **Release:** 1.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/e4cccb10532182968b21a7f6b5a26d907912a3ff))
* **Release:** 1.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/71bbab585f68a670d041039b7b35667b08fc039e))
* **Release:** 1.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8bb224074973377219b557ddac6d5481c4eda546))
* **Release:** 1.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8ae002a62c9c2c182feda23da4af0f5e0cfbd1f0))
* **Release:** 2.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/b06e7d76413c59b7dd4fffc8ea3f9f9830240e4f))
* **Release:** 2.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/4b56d329b901fa5e068ffac0d88f0f8ea486d898))
* **Release:** 2.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/f6e347b07617bf774b638b233c3aaf038ff65ccb))
* **Release:** 2.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/3374cadf6729425504f28e42790c6b972c98b83b))
* **Release:** 2.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c16d3489b1f8acc6376558095bbd00e7da3147e2))
* **Release:** 2.0.5 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a8100c137507a41a9b11165fe3936ab22d574e11))
* **Release:** 2.0.6 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/bc99473babbcf0955d6a6f4ba760dcc91ad84f8f))
* **Release:** 2.0.7 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c5931923d714e29a339b882048b5fe7192f3c3c1))
* **Release:** 3.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/72ee1e4baa9b2f1e57dd9b8b96836a8a3f66f6d3))
* **Release:** 3.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/99f13f9fb34c521e17d047bdd2198b8da7bc33f5))
* **Release:** 3.1.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/2605918d815c5dffe07db67156db3606a5919337))
* **Release:** 3.1.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/7cc441625611a297beb74c948bd6822267c6d7c8))
* **Release:** updae release.yml changed repo name ([](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))

### Release-ci

* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))
* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))
* **Release-ci:** fix Release CI Job ([](https://github.com/omnixys/authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

### Release.config.js

* **Release.config.js:** update release.config.js changed releaseBodyTemplate ([](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))

### Security-question

* **Security-question:** Add security-question model ([](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))

### Service

* **Service:** update service ([](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

### Setup

* **Setup:** initialize NestJS project with modern config and Husky pre-commit hooks ([](https://github.com/omnixys/authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

### Social login

* **Social login:** implementd social logIn ([](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## [1.0.1](https://github.com/omnixys/authentication-service/compare/v1.0.0...v1.0.1) (2026-05-01)

### Ci

* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/f07f500246d223395dff2d08b2b14a38c27e90c0))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/52717ec1558e582f029c023f5982c897f61337c5))

## 1.0.0 (2026-05-01)

### ⚠ BREAKING CHANGE

* **Fix:** authentication lint handling now validates missing step-up methods explicitly and wraps caught errors with causes.

### Adapter

* **Adapter:** Upgrade dependencies and add Valkey adapter ([](https://github.com/omnixys/authentication-service/commit/9132d62afc9b6e4e330354cfecbd29c3efdf6a96))

### Auth

* **Auth:** add admin-secured meByToken query and improve user-role handling ([](https://github.com/omnixys/authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
* **Auth:** add totp ([](https://github.com/omnixys/authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
* **Auth:** add webauthn ([](https://github.com/omnixys/authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
* **Auth:** implement GraphQL models and DTOs for User, Role, Permission ([](https://github.com/omnixys/authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))

### Auth-service

* **Auth-service:** configure OpenTelemetry service_name and unify metrics labels ([](https://github.com/omnixys/authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))

### Authentication

* **Authentication:** Add Valkey rate-limit adapter & pass client context ([](https://github.com/omnixys/authentication-service/commit/61365c83295782cdfea6072de6a1cf422c5f98c5))
* **Authentication:** authentication service v4.0.0 ([](https://github.com/omnixys/authentication-service/commit/9462025b890c077bd3e4f0423b4a16c1935c9b2f))

### Ci

* **Ci:** add release, multi-arch build/push & deploy ([](https://github.com/omnixys/authentication-service/commit/3555589f7cb9b5e588b797568009433259540b51))
* **Ci:** change secret.SERVICE to var.SERVICE ([](https://github.com/omnixys/authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
* **Ci:** add ci/cd workflow ([](https://github.com/omnixys/authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/d0594f7531087d73bf91b51687ffc086a66d053b))
* **Ci:** test ci ([](https://github.com/omnixys/authentication-service/commit/11cdc0ecd442d9165b23d8264861e9abb89f8131))
* **Ci:** update CI ([](https://github.com/omnixys/authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))

### Deploy

* **Deploy:** fix deploy.yml ([](https://github.com/omnixys/authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
* **Deploy:** test deploy.yml ([](https://github.com/omnixys/authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))

### Docker

* **Docker:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))

### Dockerfile

* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))

### Fix

* **Fix:** resolve authentication lint violations ([](https://github.com/omnixys/authentication-service/commit/90bfd702fbab24ca7546d8723b72bc524f3b2a2f))

### Graphql

* **Graphql:**  setup graphQL module with code-first schema generation ([](https://github.com/omnixys/authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))

### Husky

* **Husky:** add husky semantic ([](https://github.com/omnixys/authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
* **Husky:** update husky ([](https://github.com/omnixys/authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

### Mfa

* **Mfa:** add mfa ([](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))

### Other

* **Other:** workflow completed ([](https://github.com/omnixys/authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
* **Other:** 1.0.0 ([](https://github.com/omnixys/authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
* **Other:** add .github folder ([](https://github.com/omnixys/authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
* **Other:** add ci ([](https://github.com/omnixys/authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
* **Other:** add security Notification ([](https://github.com/omnixys/authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
* **Other:** Create deploy.yml ([](https://github.com/omnixys/authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
* **Other:** Create docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
* **Other:** init nest Project ([](https://github.com/omnixys/authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/df775ffe8c5ab413fa7331a094920a9a5fbf0cb9))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4fba9b6d3805a0ab2d5ae72d7bc8aeab79d99ef3))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/93f27f97e4af68aa9cae8b0de02ac7dcad78734f))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
* **Other:** Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([](https://github.com/omnixys/authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/authentication-service/issues/10)
* **Other:** Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/authentication-service/issues/14)
* **Other:** Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/authentication-service/issues/15)
* **Other:** Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([](https://github.com/omnixys/authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/authentication-service/issues/8)
* **Other:** Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([](https://github.com/omnixys/authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/authentication-service/issues/9)
* **Other:** Remove e2e tests; add workflow copies ([](https://github.com/omnixys/authentication-service/commit/cbd5ebf69fa9661229e4caf63f31aa675a861685))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
* **Other:** update ci ([](https://github.com/omnixys/authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
* **Other:** update CI ([](https://github.com/omnixys/authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
* **Other:** Update cors.ts ([](https://github.com/omnixys/authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
* **Other:** Update package.json ([](https://github.com/omnixys/authentication-service/commit/68b022f308f3360c820d81fed368cbc5e5f238f9))
* **Other:** Update task.yml ([](https://github.com/omnixys/authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
* **Other:** update workflow ([](https://github.com/omnixys/authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))

### Package

* **Package:** intergrated @omnixys/kafka package ([](https://github.com/omnixys/authentication-service/commit/14b7cf5eb1f97799dec2aa61f6c445997e1fe245))
* **Package:** add omnixys packages ([](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

### Prisma

* **Prisma:** add MFA ([](https://github.com/omnixys/authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
* **Prisma:** add Security Question ([](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))

### Register

* **Register:** add register flow ([](https://github.com/omnixys/authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

### Release

* **Release:** v1.0.0 ([](https://github.com/omnixys/authentication-service/commit/e29e19f9f8cdce8370fbef8c6e08c2fa8297b942))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/d751b5742c0cec8e5536b517e07f0b195ecedab5))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/586a1d23c71f0ccb7b0a428b4eaf6bd4e47562b2))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/95c5b80dcddaf488b5216ab5f8e5031e823f4be9))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/9ab94c422fc4cd801eb45bbcab1f6119fc8bf621))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/ff3bc0ace98b005829c4dbedb27310974597aeec))
* **Release:** 1.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/e4cccb10532182968b21a7f6b5a26d907912a3ff))
* **Release:** 1.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/71bbab585f68a670d041039b7b35667b08fc039e))
* **Release:** 1.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8bb224074973377219b557ddac6d5481c4eda546))
* **Release:** 1.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8ae002a62c9c2c182feda23da4af0f5e0cfbd1f0))
* **Release:** 2.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/b06e7d76413c59b7dd4fffc8ea3f9f9830240e4f))
* **Release:** 2.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/4b56d329b901fa5e068ffac0d88f0f8ea486d898))
* **Release:** 2.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/f6e347b07617bf774b638b233c3aaf038ff65ccb))
* **Release:** 2.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/3374cadf6729425504f28e42790c6b972c98b83b))
* **Release:** 2.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c16d3489b1f8acc6376558095bbd00e7da3147e2))
* **Release:** 2.0.5 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a8100c137507a41a9b11165fe3936ab22d574e11))
* **Release:** 2.0.6 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/bc99473babbcf0955d6a6f4ba760dcc91ad84f8f))
* **Release:** 2.0.7 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c5931923d714e29a339b882048b5fe7192f3c3c1))
* **Release:** 3.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/72ee1e4baa9b2f1e57dd9b8b96836a8a3f66f6d3))
* **Release:** 3.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/99f13f9fb34c521e17d047bdd2198b8da7bc33f5))
* **Release:** 3.1.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/2605918d815c5dffe07db67156db3606a5919337))
* **Release:** 3.1.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/7cc441625611a297beb74c948bd6822267c6d7c8))
* **Release:** updae release.yml changed repo name ([](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))

### Release-ci

* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))
* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))
* **Release-ci:** fix Release CI Job ([](https://github.com/omnixys/authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

### Release.config.js

* **Release.config.js:** update release.config.js changed releaseBodyTemplate ([](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))

### Security-question

* **Security-question:** Add security-question model ([](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))

### Service

* **Service:** update service ([](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

### Setup

* **Setup:** initialize NestJS project with modern config and Husky pre-commit hooks ([](https://github.com/omnixys/authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

### Social login

* **Social login:** implementd social logIn ([](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## 1.0.0 (2026-05-01)

### ⚠ BREAKING CHANGE

* **Fix:** authentication lint handling now validates missing step-up methods explicitly and wraps caught errors with causes.

### Adapter

* **Adapter:** Upgrade dependencies and add Valkey adapter ([](https://github.com/omnixys/authentication-service/commit/9132d62afc9b6e4e330354cfecbd29c3efdf6a96))

### Auth

* **Auth:** add admin-secured meByToken query and improve user-role handling ([](https://github.com/omnixys/authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
* **Auth:** add totp ([](https://github.com/omnixys/authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
* **Auth:** add webauthn ([](https://github.com/omnixys/authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
* **Auth:** implement GraphQL models and DTOs for User, Role, Permission ([](https://github.com/omnixys/authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))

### Auth-service

* **Auth-service:** configure OpenTelemetry service_name and unify metrics labels ([](https://github.com/omnixys/authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))

### Authentication

* **Authentication:** Add Valkey rate-limit adapter & pass client context ([](https://github.com/omnixys/authentication-service/commit/61365c83295782cdfea6072de6a1cf422c5f98c5))
* **Authentication:** authentication service v4.0.0 ([](https://github.com/omnixys/authentication-service/commit/9462025b890c077bd3e4f0423b4a16c1935c9b2f))

### Ci

* **Ci:** add release, multi-arch build/push & deploy ([](https://github.com/omnixys/authentication-service/commit/3555589f7cb9b5e588b797568009433259540b51))
* **Ci:** change secret.SERVICE to var.SERVICE ([](https://github.com/omnixys/authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
* **Ci:** add ci/cd workflow ([](https://github.com/omnixys/authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
* **Ci:** update CI ([](https://github.com/omnixys/authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))

### Deploy

* **Deploy:** fix deploy.yml ([](https://github.com/omnixys/authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
* **Deploy:** test deploy.yml ([](https://github.com/omnixys/authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))

### Docker

* **Docker:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))

### Dockerfile

* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))

### Fix

* **Fix:** resolve authentication lint violations ([](https://github.com/omnixys/authentication-service/commit/90bfd702fbab24ca7546d8723b72bc524f3b2a2f))

### Graphql

* **Graphql:**  setup graphQL module with code-first schema generation ([](https://github.com/omnixys/authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))

### Husky

* **Husky:** add husky semantic ([](https://github.com/omnixys/authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
* **Husky:** update husky ([](https://github.com/omnixys/authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

### Mfa

* **Mfa:** add mfa ([](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))

### Other

* **Other:** workflow completed ([](https://github.com/omnixys/authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
* **Other:** 1.0.0 ([](https://github.com/omnixys/authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
* **Other:** add .github folder ([](https://github.com/omnixys/authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
* **Other:** add ci ([](https://github.com/omnixys/authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
* **Other:** add security Notification ([](https://github.com/omnixys/authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
* **Other:** Create deploy.yml ([](https://github.com/omnixys/authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
* **Other:** Create docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
* **Other:** init nest Project ([](https://github.com/omnixys/authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/df775ffe8c5ab413fa7331a094920a9a5fbf0cb9))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4fba9b6d3805a0ab2d5ae72d7bc8aeab79d99ef3))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/93f27f97e4af68aa9cae8b0de02ac7dcad78734f))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
* **Other:** Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([](https://github.com/omnixys/authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/authentication-service/issues/10)
* **Other:** Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/authentication-service/issues/14)
* **Other:** Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/authentication-service/issues/15)
* **Other:** Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([](https://github.com/omnixys/authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/authentication-service/issues/8)
* **Other:** Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([](https://github.com/omnixys/authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/authentication-service/issues/9)
* **Other:** Remove e2e tests; add workflow copies ([](https://github.com/omnixys/authentication-service/commit/cbd5ebf69fa9661229e4caf63f31aa675a861685))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
* **Other:** update ci ([](https://github.com/omnixys/authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
* **Other:** update CI ([](https://github.com/omnixys/authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
* **Other:** Update cors.ts ([](https://github.com/omnixys/authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
* **Other:** Update package.json ([](https://github.com/omnixys/authentication-service/commit/68b022f308f3360c820d81fed368cbc5e5f238f9))
* **Other:** Update task.yml ([](https://github.com/omnixys/authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
* **Other:** update workflow ([](https://github.com/omnixys/authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))

### Package

* **Package:** intergrated @omnixys/kafka package ([](https://github.com/omnixys/authentication-service/commit/14b7cf5eb1f97799dec2aa61f6c445997e1fe245))
* **Package:** add omnixys packages ([](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

### Prisma

* **Prisma:** add MFA ([](https://github.com/omnixys/authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
* **Prisma:** add Security Question ([](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))

### Register

* **Register:** add register flow ([](https://github.com/omnixys/authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

### Release

* **Release:** v1.0.0 ([](https://github.com/omnixys/authentication-service/commit/e29e19f9f8cdce8370fbef8c6e08c2fa8297b942))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/586a1d23c71f0ccb7b0a428b4eaf6bd4e47562b2))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/95c5b80dcddaf488b5216ab5f8e5031e823f4be9))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/9ab94c422fc4cd801eb45bbcab1f6119fc8bf621))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/ff3bc0ace98b005829c4dbedb27310974597aeec))
* **Release:** 1.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/e4cccb10532182968b21a7f6b5a26d907912a3ff))
* **Release:** 1.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/71bbab585f68a670d041039b7b35667b08fc039e))
* **Release:** 1.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8bb224074973377219b557ddac6d5481c4eda546))
* **Release:** 1.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8ae002a62c9c2c182feda23da4af0f5e0cfbd1f0))
* **Release:** 2.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/b06e7d76413c59b7dd4fffc8ea3f9f9830240e4f))
* **Release:** 2.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/4b56d329b901fa5e068ffac0d88f0f8ea486d898))
* **Release:** 2.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/f6e347b07617bf774b638b233c3aaf038ff65ccb))
* **Release:** 2.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/3374cadf6729425504f28e42790c6b972c98b83b))
* **Release:** 2.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c16d3489b1f8acc6376558095bbd00e7da3147e2))
* **Release:** 2.0.5 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a8100c137507a41a9b11165fe3936ab22d574e11))
* **Release:** 2.0.6 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/bc99473babbcf0955d6a6f4ba760dcc91ad84f8f))
* **Release:** 2.0.7 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c5931923d714e29a339b882048b5fe7192f3c3c1))
* **Release:** 3.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/72ee1e4baa9b2f1e57dd9b8b96836a8a3f66f6d3))
* **Release:** 3.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/99f13f9fb34c521e17d047bdd2198b8da7bc33f5))
* **Release:** 3.1.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/2605918d815c5dffe07db67156db3606a5919337))
* **Release:** 3.1.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/7cc441625611a297beb74c948bd6822267c6d7c8))
* **Release:** updae release.yml changed repo name ([](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))

### Release-ci

* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))
* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))
* **Release-ci:** fix Release CI Job ([](https://github.com/omnixys/authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

### Release.config.js

* **Release.config.js:** update release.config.js changed releaseBodyTemplate ([](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))

### Security-question

* **Security-question:** Add security-question model ([](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))

### Service

* **Service:** update service ([](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

### Setup

* **Setup:** initialize NestJS project with modern config and Husky pre-commit hooks ([](https://github.com/omnixys/authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

### Social login

* **Social login:** implementd social logIn ([](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## 1.0.0 (2026-04-29)

### ⚠ BREAKING CHANGE

* **Fix:** authentication lint handling now validates missing step-up methods explicitly and wraps caught errors with causes.

### Adapter

* **Adapter:** Upgrade dependencies and add Valkey adapter ([](https://github.com/omnixys/authentication-service/commit/9132d62afc9b6e4e330354cfecbd29c3efdf6a96))

### Auth

* **Auth:** add admin-secured meByToken query and improve user-role handling ([](https://github.com/omnixys/authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
* **Auth:** add totp ([](https://github.com/omnixys/authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
* **Auth:** add webauthn ([](https://github.com/omnixys/authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
* **Auth:** implement GraphQL models and DTOs for User, Role, Permission ([](https://github.com/omnixys/authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))

### Auth-service

* **Auth-service:** configure OpenTelemetry service_name and unify metrics labels ([](https://github.com/omnixys/authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))

### Authentication

* **Authentication:** Add Valkey rate-limit adapter & pass client context ([](https://github.com/omnixys/authentication-service/commit/61365c83295782cdfea6072de6a1cf422c5f98c5))
* **Authentication:** authentication service v4.0.0 ([](https://github.com/omnixys/authentication-service/commit/9462025b890c077bd3e4f0423b4a16c1935c9b2f))

### Ci

* **Ci:** change secret.SERVICE to var.SERVICE ([](https://github.com/omnixys/authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
* **Ci:** add ci/cd workflow ([](https://github.com/omnixys/authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
* **Ci:** update CI ([](https://github.com/omnixys/authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))

### Deploy

* **Deploy:** fix deploy.yml ([](https://github.com/omnixys/authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
* **Deploy:** test deploy.yml ([](https://github.com/omnixys/authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))

### Docker

* **Docker:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))

### Dockerfile

* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))

### Fix

* **Fix:** resolve authentication lint violations ([](https://github.com/omnixys/authentication-service/commit/90bfd702fbab24ca7546d8723b72bc524f3b2a2f))

### Graphql

* **Graphql:**  setup graphQL module with code-first schema generation ([](https://github.com/omnixys/authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))

### Husky

* **Husky:** add husky semantic ([](https://github.com/omnixys/authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
* **Husky:** update husky ([](https://github.com/omnixys/authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

### Mfa

* **Mfa:** add mfa ([](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))

### Other

* **Other:** workflow completed ([](https://github.com/omnixys/authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
* **Other:** 1.0.0 ([](https://github.com/omnixys/authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
* **Other:** add .github folder ([](https://github.com/omnixys/authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
* **Other:** add ci ([](https://github.com/omnixys/authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
* **Other:** add security Notification ([](https://github.com/omnixys/authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
* **Other:** Create deploy.yml ([](https://github.com/omnixys/authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
* **Other:** Create docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
* **Other:** init nest Project ([](https://github.com/omnixys/authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4fba9b6d3805a0ab2d5ae72d7bc8aeab79d99ef3))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/93f27f97e4af68aa9cae8b0de02ac7dcad78734f))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
* **Other:** Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([](https://github.com/omnixys/authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/authentication-service/issues/10)
* **Other:** Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/authentication-service/issues/14)
* **Other:** Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/authentication-service/issues/15)
* **Other:** Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([](https://github.com/omnixys/authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/authentication-service/issues/8)
* **Other:** Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([](https://github.com/omnixys/authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/authentication-service/issues/9)
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
* **Other:** update ci ([](https://github.com/omnixys/authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
* **Other:** update CI ([](https://github.com/omnixys/authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
* **Other:** Update cors.ts ([](https://github.com/omnixys/authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
* **Other:** Update package.json ([](https://github.com/omnixys/authentication-service/commit/68b022f308f3360c820d81fed368cbc5e5f238f9))
* **Other:** Update task.yml ([](https://github.com/omnixys/authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
* **Other:** update workflow ([](https://github.com/omnixys/authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))

### Package

* **Package:** intergrated @omnixys/kafka package ([](https://github.com/omnixys/authentication-service/commit/14b7cf5eb1f97799dec2aa61f6c445997e1fe245))
* **Package:** add omnixys packages ([](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

### Prisma

* **Prisma:** add MFA ([](https://github.com/omnixys/authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
* **Prisma:** add Security Question ([](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))

### Register

* **Register:** add register flow ([](https://github.com/omnixys/authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

### Release

* **Release:** v1.0.0 ([](https://github.com/omnixys/authentication-service/commit/e29e19f9f8cdce8370fbef8c6e08c2fa8297b942))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/95c5b80dcddaf488b5216ab5f8e5031e823f4be9))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/9ab94c422fc4cd801eb45bbcab1f6119fc8bf621))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/ff3bc0ace98b005829c4dbedb27310974597aeec))
* **Release:** 1.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/e4cccb10532182968b21a7f6b5a26d907912a3ff))
* **Release:** 1.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/71bbab585f68a670d041039b7b35667b08fc039e))
* **Release:** 1.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8bb224074973377219b557ddac6d5481c4eda546))
* **Release:** 1.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8ae002a62c9c2c182feda23da4af0f5e0cfbd1f0))
* **Release:** 2.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/b06e7d76413c59b7dd4fffc8ea3f9f9830240e4f))
* **Release:** 2.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/4b56d329b901fa5e068ffac0d88f0f8ea486d898))
* **Release:** 2.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/f6e347b07617bf774b638b233c3aaf038ff65ccb))
* **Release:** 2.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/3374cadf6729425504f28e42790c6b972c98b83b))
* **Release:** 2.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c16d3489b1f8acc6376558095bbd00e7da3147e2))
* **Release:** 2.0.5 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a8100c137507a41a9b11165fe3936ab22d574e11))
* **Release:** 2.0.6 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/bc99473babbcf0955d6a6f4ba760dcc91ad84f8f))
* **Release:** 2.0.7 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c5931923d714e29a339b882048b5fe7192f3c3c1))
* **Release:** 3.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/72ee1e4baa9b2f1e57dd9b8b96836a8a3f66f6d3))
* **Release:** 3.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/99f13f9fb34c521e17d047bdd2198b8da7bc33f5))
* **Release:** 3.1.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/2605918d815c5dffe07db67156db3606a5919337))
* **Release:** 3.1.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/7cc441625611a297beb74c948bd6822267c6d7c8))
* **Release:** updae release.yml changed repo name ([](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))

### Release-ci

* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))
* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))
* **Release-ci:** fix Release CI Job ([](https://github.com/omnixys/authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

### Release.config.js

* **Release.config.js:** update release.config.js changed releaseBodyTemplate ([](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))

### Security-question

* **Security-question:** Add security-question model ([](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))

### Service

* **Service:** update service ([](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

### Setup

* **Setup:** initialize NestJS project with modern config and Husky pre-commit hooks ([](https://github.com/omnixys/authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

### Social login

* **Social login:** implementd social logIn ([](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## 1.0.0 (2026-04-29)

### Adapter

* **Adapter:** Upgrade dependencies and add Valkey adapter ([](https://github.com/omnixys/authentication-service/commit/9132d62afc9b6e4e330354cfecbd29c3efdf6a96))

### Auth

* **Auth:** add admin-secured meByToken query and improve user-role handling ([](https://github.com/omnixys/authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
* **Auth:** add totp ([](https://github.com/omnixys/authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
* **Auth:** add webauthn ([](https://github.com/omnixys/authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
* **Auth:** implement GraphQL models and DTOs for User, Role, Permission ([](https://github.com/omnixys/authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))

### Auth-service

* **Auth-service:** configure OpenTelemetry service_name and unify metrics labels ([](https://github.com/omnixys/authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))

### Authentication

* **Authentication:** Add Valkey rate-limit adapter & pass client context ([](https://github.com/omnixys/authentication-service/commit/61365c83295782cdfea6072de6a1cf422c5f98c5))
* **Authentication:** authentication service v4.0.0 ([](https://github.com/omnixys/authentication-service/commit/9462025b890c077bd3e4f0423b4a16c1935c9b2f))

### Ci

* **Ci:** change secret.SERVICE to var.SERVICE ([](https://github.com/omnixys/authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
* **Ci:** add ci/cd workflow ([](https://github.com/omnixys/authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
* **Ci:** update CI ([](https://github.com/omnixys/authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
* **Ci:** update release.yml ([](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))

### Deploy

* **Deploy:** fix deploy.yml ([](https://github.com/omnixys/authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
* **Deploy:** test deploy.yml ([](https://github.com/omnixys/authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))

### Docker

* **Docker:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))

### Dockerfile

* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
* **Dockerfile:** update dockerfile ([](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))

### Graphql

* **Graphql:**  setup graphQL module with code-first schema generation ([](https://github.com/omnixys/authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))

### Husky

* **Husky:** add husky semantic ([](https://github.com/omnixys/authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
* **Husky:** update husky ([](https://github.com/omnixys/authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

### Mfa

* **Mfa:** add mfa ([](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))

### Other

* **Other:** workflow completed ([](https://github.com/omnixys/authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
* **Other:** 1.0.0 ([](https://github.com/omnixys/authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
* **Other:** add .github folder ([](https://github.com/omnixys/authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
* **Other:** add ci ([](https://github.com/omnixys/authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
* **Other:** add security Notification ([](https://github.com/omnixys/authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
* **Other:** Create deploy.yml ([](https://github.com/omnixys/authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
* **Other:** Create docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
* **Other:** init nest Project ([](https://github.com/omnixys/authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/93f27f97e4af68aa9cae8b0de02ac7dcad78734f))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))
* **Other:** Merge branch 'main' of https://github.com/omnixys/authentication-service ([](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
* **Other:** Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([](https://github.com/omnixys/authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
* **Other:** Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([](https://github.com/omnixys/authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/authentication-service/issues/10)
* **Other:** Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/authentication-service/issues/14)
* **Other:** Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([](https://github.com/omnixys/authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/authentication-service/issues/15)
* **Other:** Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([](https://github.com/omnixys/authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/authentication-service/issues/8)
* **Other:** Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([](https://github.com/omnixys/authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/authentication-service/issues/9)
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
* **Other:** update ([](https://github.com/omnixys/authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
* **Other:** update ci ([](https://github.com/omnixys/authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
* **Other:** update CI ([](https://github.com/omnixys/authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
* **Other:** Update ci.yaml ([](https://github.com/omnixys/authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
* **Other:** Update cors.ts ([](https://github.com/omnixys/authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
* **Other:** Update deploy.yml ([](https://github.com/omnixys/authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
* **Other:** Update docker-build.yaml ([](https://github.com/omnixys/authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
* **Other:** Update task.yml ([](https://github.com/omnixys/authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
* **Other:** update workflow ([](https://github.com/omnixys/authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))

### Package

* **Package:** intergrated @omnixys/kafka package ([](https://github.com/omnixys/authentication-service/commit/14b7cf5eb1f97799dec2aa61f6c445997e1fe245))
* **Package:** add omnixys packages ([](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

### Prisma

* **Prisma:** add MFA ([](https://github.com/omnixys/authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
* **Prisma:** update prisma schema ([](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
* **Prisma:** add Security Question ([](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))

### Register

* **Register:** add register flow ([](https://github.com/omnixys/authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

### Release

* **Release:** v1.0.0 ([](https://github.com/omnixys/authentication-service/commit/e29e19f9f8cdce8370fbef8c6e08c2fa8297b942))
* **Release:** 1.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/9ab94c422fc4cd801eb45bbcab1f6119fc8bf621))
* **Release:** 1.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/ff3bc0ace98b005829c4dbedb27310974597aeec))
* **Release:** 1.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/e4cccb10532182968b21a7f6b5a26d907912a3ff))
* **Release:** 1.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/71bbab585f68a670d041039b7b35667b08fc039e))
* **Release:** 1.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8bb224074973377219b557ddac6d5481c4eda546))
* **Release:** 1.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/8ae002a62c9c2c182feda23da4af0f5e0cfbd1f0))
* **Release:** 2.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/b06e7d76413c59b7dd4fffc8ea3f9f9830240e4f))
* **Release:** 2.0.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/4b56d329b901fa5e068ffac0d88f0f8ea486d898))
* **Release:** 2.0.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/f6e347b07617bf774b638b233c3aaf038ff65ccb))
* **Release:** 2.0.3 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/3374cadf6729425504f28e42790c6b972c98b83b))
* **Release:** 2.0.4 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c16d3489b1f8acc6376558095bbd00e7da3147e2))
* **Release:** 2.0.5 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/a8100c137507a41a9b11165fe3936ab22d574e11))
* **Release:** 2.0.6 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/bc99473babbcf0955d6a6f4ba760dcc91ad84f8f))
* **Release:** 2.0.7 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/c5931923d714e29a339b882048b5fe7192f3c3c1))
* **Release:** 3.0.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/72ee1e4baa9b2f1e57dd9b8b96836a8a3f66f6d3))
* **Release:** 3.1.0 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/99f13f9fb34c521e17d047bdd2198b8da7bc33f5))
* **Release:** 3.1.1 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/2605918d815c5dffe07db67156db3606a5919337))
* **Release:** 3.1.2 [skip ci] ([](https://github.com/omnixys/authentication-service/commit/7cc441625611a297beb74c948bd6822267c6d7c8))
* **Release:** updae release.yml changed repo name ([](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))

### Release-ci

* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))
* **Release-ci:** add @semantic-release/npm ([](https://github.com/omnixys/authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))
* **Release-ci:** fix Release CI Job ([](https://github.com/omnixys/authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

### Release.config.js

* **Release.config.js:** update release.config.js changed releaseBodyTemplate ([](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))

### Security-question

* **Security-question:** Add security-question model ([](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))

### Service

* **Service:** update service ([](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))
* **Service:** major Service update ([](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

### Setup

* **Setup:** initialize NestJS project with modern config and Husky pre-commit hooks ([](https://github.com/omnixys/authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

### Social login

* **Social login:** implementd social logIn ([](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## <small>3.1.2 (2026-03-13)</small>

- Merge branch 'main' of https://github.com/omnixys/authentication-service ([d78caafae79181b9d5818b3c6f91e9999f205b10](https://github.com/omnixys/authentication-service/commit/d78caafae79181b9d5818b3c6f91e9999f205b10))
- fix(service): major Service update ([81c8e00f62bc696415f4b36a0f3fe84d4f9e738a](https://github.com/omnixys/authentication-service/commit/81c8e00f62bc696415f4b36a0f3fe84d4f9e738a))

## <small>3.1.1 (2026-03-13)</small>

- fix(service): major Service update ([70647e7527a1525c4349f2eb55224d2029dd655f](https://github.com/omnixys/authentication-service/commit/70647e7527a1525c4349f2eb55224d2029dd655f))

## 3.1.0 (2026-03-13)

- Merge branch 'main' of https://github.com/omnixys/authentication-service ([4762b57406fcbfe034ead4d4979cf61c47297117](https://github.com/omnixys/authentication-service/commit/4762b57406fcbfe034ead4d4979cf61c47297117))
- feat(package): add omnixys packages ([f3272ae10f8023e879c4678d1e126e15e4bc424a](https://github.com/omnixys/authentication-service/commit/f3272ae10f8023e879c4678d1e126e15e4bc424a))

## 3.0.0 (2026-03-12)

- breaking(service): update service ([b91118864db2f42cdc197d7cdb14a19f20fb6be9](https://github.com/omnixys/authentication-service/commit/b91118864db2f42cdc197d7cdb14a19f20fb6be9))

## <small>2.0.7 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([416b75243a4a14d48631e763cf2372d93aeba425](https://github.com/omnixys/authentication-service/commit/416b75243a4a14d48631e763cf2372d93aeba425))

## <small>2.0.6 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([c672ebbba30e37912ed33f4fef1d806f6dbcc5b9](https://github.com/omnixys/authentication-service/commit/c672ebbba30e37912ed33f4fef1d806f6dbcc5b9))
- Merge branch 'main' of https://github.com/omnixys/authentication-service ([9ffe0cdace890ed65b3883feddf78df3e719673d](https://github.com/omnixys/authentication-service/commit/9ffe0cdace890ed65b3883feddf78df3e719673d))

## <small>2.0.5 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([df14c2e565dcfe6f81042fe9df37cd3aac287a13](https://github.com/omnixys/authentication-service/commit/df14c2e565dcfe6f81042fe9df37cd3aac287a13))
- Merge branch 'main' of https://github.com/omnixys/authentication-service ([e99dd597c7d11baed8ca98acff86f2820c4f81ce](https://github.com/omnixys/authentication-service/commit/e99dd597c7d11baed8ca98acff86f2820c4f81ce))

## <small>2.0.4 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([5d02e051015b371c162f21a0c43a4e1e64623b39](https://github.com/omnixys/authentication-service/commit/5d02e051015b371c162f21a0c43a4e1e64623b39))

## <small>2.0.3 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([9de6706e69c414bcefc997ed17815f3f165c85e3](https://github.com/omnixys/authentication-service/commit/9de6706e69c414bcefc997ed17815f3f165c85e3))
- Merge branch 'main' of https://github.com/omnixys/authentication-service ([cefc9c68519168a58006064ec23a40348312e9f8](https://github.com/omnixys/authentication-service/commit/cefc9c68519168a58006064ec23a40348312e9f8))

## <small>2.0.2 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([744038e32594558e0a8096948e8be7b1c967a2e8](https://github.com/omnixys/authentication-service/commit/744038e32594558e0a8096948e8be7b1c967a2e8))
- Merge branch 'main' of https://github.com/omnixys/authentication-service ([7211fec6b98194ca5500a04be42585970e683fa1](https://github.com/omnixys/authentication-service/commit/7211fec6b98194ca5500a04be42585970e683fa1))

## <small>2.0.1 (2026-03-10)</small>

- fix(dockerfile): update dockerfile ([6dd1b95b767a0998c3f8a6856128e85b6dd9e39f](https://github.com/omnixys/authentication-service/commit/6dd1b95b767a0998c3f8a6856128e85b6dd9e39f))
- Merge branch 'main' of https://github.com/omnixys/authentication-service ([4d07ce22d83853c392650e4642aed180ce2311ce](https://github.com/omnixys/authentication-service/commit/4d07ce22d83853c392650e4642aed180ce2311ce))

## 2.0.0 (2026-03-10)

- fix(ci): update release.yml ([1b77206c13d8ea2a5fdd27aa241f457e2510988b](https://github.com/omnixys/authentication-service/commit/1b77206c13d8ea2a5fdd27aa241f457e2510988b))
- fix(ci): update release.yml ([0be61fe0cf84027e75cedd5044f56d966a3bcda3](https://github.com/omnixys/authentication-service/commit/0be61fe0cf84027e75cedd5044f56d966a3bcda3))
- fix(docker): update dockerfile ([0fa13704206df3ee3a4d266a8f18bfa370ac8282](https://github.com/omnixys/authentication-service/commit/0fa13704206df3ee3a4d266a8f18bfa370ac8282))
- feat(mfa): add mfa ([cec00158decadde0b2f12cb12a3c3d13d4b5b78b](https://github.com/omnixys/authentication-service/commit/cec00158decadde0b2f12cb12a3c3d13d4b5b78b))
- Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([3b15b278f009247d2ea486e75815984e825dee05](https://github.com/omnixys/authentication-service/commit/3b15b278f009247d2ea486e75815984e825dee05))
- breaking(prisma): update prisma schema ([6545a82fa92b4f29ebe50cbe84883a348321d673](https://github.com/omnixys/authentication-service/commit/6545a82fa92b4f29ebe50cbe84883a348321d673))
- feat(prisma): add Security Question ([f5e65361a40b640217e3f9dcc362df3dc042e5ed](https://github.com/omnixys/authentication-service/commit/f5e65361a40b640217e3f9dcc362df3dc042e5ed))
- ci(release): updae release.yml changed repo name ([297be0fdac435a82f693bc21f3a530931241bf42](https://github.com/omnixys/authentication-service/commit/297be0fdac435a82f693bc21f3a530931241bf42))
- chore(release.config.js): update release.config.js changed releaseBodyTemplate ([b5fe0f2843bef09a10f843341c9628fbffc0586f](https://github.com/omnixys/authentication-service/commit/b5fe0f2843bef09a10f843341c9628fbffc0586f))
- feat(security-question): Add security-question model ([5374b6aa50fb7bfddfe45eaf82f4825eb86fba67](https://github.com/omnixys/authentication-service/commit/5374b6aa50fb7bfddfe45eaf82f4825eb86fba67))
- feat(social login): implementd social logIn ([23a05ef60100d7a129ee26a0980d1dd6d3d46ec2](https://github.com/omnixys/authentication-service/commit/23a05ef60100d7a129ee26a0980d1dd6d3d46ec2))

## 1.1.0 (2026-03-01)

- feat(register): add register flow ([f886677d8a19de95046c42136613d2b6f2b36c4b](https://github.com/omnixys/omnixys-authentication-service/commit/f886677d8a19de95046c42136613d2b6f2b36c4b))

## <small>1.0.4 (2026-02-26)</small>

- Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([c200d2ee487893c0cac584d55330ce73e882252a](https://github.com/omnixys/omnixys-authentication-service/commit/c200d2ee487893c0cac584d55330ce73e882252a))
- fix(release-ci): add @semantic-release/npm ([50554eb2a39225e3b3f930d209b19a131fb84617](https://github.com/omnixys/omnixys-authentication-service/commit/50554eb2a39225e3b3f930d209b19a131fb84617))

## <small>1.0.3 (2026-02-26)</small>

- Merge branch 'main' of https://github.com/omnixys/omnixys-authentication-service ([74e5a281d052de0015b350f1a82bdb40513d269c](https://github.com/omnixys/omnixys-authentication-service/commit/74e5a281d052de0015b350f1a82bdb40513d269c))
- fix(release-ci): add @semantic-release/npm ([4e6dcdea40e53f6dfa932a2764b9fd9114033bc2](https://github.com/omnixys/omnixys-authentication-service/commit/4e6dcdea40e53f6dfa932a2764b9fd9114033bc2))

## <small>1.0.2 (2026-02-26)</small>

- fix(release-ci): fix Release CI Job ([e1b2c43b2708250b0915402e489cce7aa8743929](https://github.com/omnixys/omnixys-authentication-service/commit/e1b2c43b2708250b0915402e489cce7aa8743929))

## <small>1.0.1 (2026-02-25)</small>

- fix(ci): update CI ([ac9375da285ed4719572798672d28cdb51757327](https://github.com/omnixys/omnixys-authentication-service/commit/ac9375da285ed4719572798672d28cdb51757327))
- ci(deploy): fix deploy.yml ([797850d4504801d5836f31afd06f74ad615df4fb](https://github.com/omnixys/omnixys-authentication-service/commit/797850d4504801d5836f31afd06f74ad615df4fb))
- ci(deploy): test deploy.yml ([7f1a15878f85418bc5d81e2fe8f99a12b3a383f7](https://github.com/omnixys/omnixys-authentication-service/commit/7f1a15878f85418bc5d81e2fe8f99a12b3a383f7))
- chore(husky): update husky ([15d89f9816f20fcdefad95cb179becc1a1b5d745](https://github.com/omnixys/omnixys-authentication-service/commit/15d89f9816f20fcdefad95cb179becc1a1b5d745))

## 1.0.0 (2026-02-25)

- feat(auth): add admin-secured meByToken query and improve user-role handling ([a4b0b6ce4394fa55137629e947bc83e4de19923e](https://github.com/omnixys/omnixys-authentication-service/commit/a4b0b6ce4394fa55137629e947bc83e4de19923e))
- feat(auth): add totp ([555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2](https://github.com/omnixys/omnixys-authentication-service/commit/555c1ccc14fc4a2ff1ba0ca33d552f24b8b1a8c2))
- feat(auth): add webauthn ([1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd](https://github.com/omnixys/omnixys-authentication-service/commit/1988283559a9ba83edbf78e3b0a4fd6e26ea6bdd))
- feat(auth): implement GraphQL models and DTOs for User, Role, Permission ([27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd](https://github.com/omnixys/omnixys-authentication-service/commit/27021fc5238f3d7db45c1c40ac4d61dd2e37ebdd))
- feat(auth-service): configure OpenTelemetry service_name and unify metrics labels ([63677b8bca336a7d6be6ea1a28328058259b2818](https://github.com/omnixys/omnixys-authentication-service/commit/63677b8bca336a7d6be6ea1a28328058259b2818))
- ci(ci): change secret.SERVICE to var.SERVICE ([f263e8ddac8614df615e6fca70903b8ebcfc5f24](https://github.com/omnixys/omnixys-authentication-service/commit/f263e8ddac8614df615e6fca70903b8ebcfc5f24))
- feat(ci): add ci/cd workflow ([7e00765c0b828be64edcba1cc4e086d8d6fbaa98](https://github.com/omnixys/omnixys-authentication-service/commit/7e00765c0b828be64edcba1cc4e086d8d6fbaa98))
- feat(graphql): setup graphQL module with code-first schema generation ([7ce98e49ad98e56fbd65a9b44f107e335760ddf5](https://github.com/omnixys/omnixys-authentication-service/commit/7ce98e49ad98e56fbd65a9b44f107e335760ddf5))
- chore(husky): add husky semantic ([284fe783c14f8219f509b2358ab040a9b7e86fd8](https://github.com/omnixys/omnixys-authentication-service/commit/284fe783c14f8219f509b2358ab040a9b7e86fd8))
- feat(): workflow completed ([f71b1498463191633075bc6037ddc33ec4368949](https://github.com/omnixys/omnixys-authentication-service/commit/f71b1498463191633075bc6037ddc33ec4368949))
- 1.0.0 ([2eaef260e2015dfdd21268a6d682e3f8e14b3fbe](https://github.com/omnixys/omnixys-authentication-service/commit/2eaef260e2015dfdd21268a6d682e3f8e14b3fbe))
- add .github folder ([e130be485b1d59a2d713415d15b30f51a08659a0](https://github.com/omnixys/omnixys-authentication-service/commit/e130be485b1d59a2d713415d15b30f51a08659a0))
- add ci ([0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc](https://github.com/omnixys/omnixys-authentication-service/commit/0e15ea6fd57ac2349908a5c3cff28f52a8dd90bc))
- add security Notification ([5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660](https://github.com/omnixys/omnixys-authentication-service/commit/5fb11aa6cf7a3d2e48b9d36dc7ebd66098cab660))
- Create deploy.yml ([352b271ee44e5e8a497bfdb5b186c61e6acc6c9c](https://github.com/omnixys/omnixys-authentication-service/commit/352b271ee44e5e8a497bfdb5b186c61e6acc6c9c))
- Create docker-build.yaml ([88bdfdb83e40801220d98d422b95c46e947ace38](https://github.com/omnixys/omnixys-authentication-service/commit/88bdfdb83e40801220d98d422b95c46e947ace38))
- init nest Project ([f72f97aface754513634309a66a0902bfa017dab](https://github.com/omnixys/omnixys-authentication-service/commit/f72f97aface754513634309a66a0902bfa017dab))
- Merge pull request #10 from omnixys/3-auth-task-define-models-and-dtos-for-user-role-permission ([556fd375889a465b6b9b41ab51eea03764e5bec6](https://github.com/omnixys/omnixys-authentication-service/commit/556fd375889a465b6b9b41ab51eea03764e5bec6)), closes [#10](https://github.com/omnixys/omnixys-authentication-service/issues/10)
- Merge pull request #14 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([8dee96414b49e221538f64c7a4dc89945ed456c2](https://github.com/omnixys/omnixys-authentication-service/commit/8dee96414b49e221538f64c7a4dc89945ed456c2)), closes [#14](https://github.com/omnixys/omnixys-authentication-service/issues/14)
- Merge pull request #15 from omnixys/13-auth-task-refactor-authentication-remove-keycloak-connect-implement-custom-jwt-guards ([abd17a3ba59583ebaba0b07c9a36b42ba488093a](https://github.com/omnixys/omnixys-authentication-service/commit/abd17a3ba59583ebaba0b07c9a36b42ba488093a)), closes [#15](https://github.com/omnixys/omnixys-authentication-service/issues/15)
- Merge pull request #8 from omnixys/1-auth-task-initialize-nestjs-project-and-modern-configuration ([bda342023472d4457f5842cb5049fe343549a84d](https://github.com/omnixys/omnixys-authentication-service/commit/bda342023472d4457f5842cb5049fe343549a84d)), closes [#8](https://github.com/omnixys/omnixys-authentication-service/issues/8)
- Merge pull request #9 from omnixys/2-auth-task-setup-graphql-with-code-first-schema-generation ([6f6ab148a553ef3c0c1479a99de805f87df92044](https://github.com/omnixys/omnixys-authentication-service/commit/6f6ab148a553ef3c0c1479a99de805f87df92044)), closes [#9](https://github.com/omnixys/omnixys-authentication-service/issues/9)
- update ([0f527dfd60a61c1ed38f88ec78a28f480f7d5643](https://github.com/omnixys/omnixys-authentication-service/commit/0f527dfd60a61c1ed38f88ec78a28f480f7d5643))
- update ([3c4df9a33cc13732331741485a67251fa8620b43](https://github.com/omnixys/omnixys-authentication-service/commit/3c4df9a33cc13732331741485a67251fa8620b43))
- update ci ([068681a0633985057d0e262e8a4fa11000377c90](https://github.com/omnixys/omnixys-authentication-service/commit/068681a0633985057d0e262e8a4fa11000377c90))
- update CI ([9ffe0217b24f949e41686283c49509d6d3c18646](https://github.com/omnixys/omnixys-authentication-service/commit/9ffe0217b24f949e41686283c49509d6d3c18646))
- Update ci.yaml ([8a067185de61ae11284f62a3632271d402c9699b](https://github.com/omnixys/omnixys-authentication-service/commit/8a067185de61ae11284f62a3632271d402c9699b))
- Update ci.yaml ([91ffdb12890c0a8db56f97aa79c9cb23b82b0754](https://github.com/omnixys/omnixys-authentication-service/commit/91ffdb12890c0a8db56f97aa79c9cb23b82b0754))
- Update ci.yaml ([f55535d6aeab7f2f560240f576a6b162ae9ab89a](https://github.com/omnixys/omnixys-authentication-service/commit/f55535d6aeab7f2f560240f576a6b162ae9ab89a))
- Update ci.yaml ([26b64602db974cb76d07969826850c8bef0f2074](https://github.com/omnixys/omnixys-authentication-service/commit/26b64602db974cb76d07969826850c8bef0f2074))
- Update ci.yaml ([0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6](https://github.com/omnixys/omnixys-authentication-service/commit/0f075fa3ba5b7a4b3e6a61ae1b0d85fc00832ac6))
- Update ci.yaml ([6b5fb38998c7b2b3416644b551fd23986528895b](https://github.com/omnixys/omnixys-authentication-service/commit/6b5fb38998c7b2b3416644b551fd23986528895b))
- Update cors.ts ([4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc](https://github.com/omnixys/omnixys-authentication-service/commit/4a2c3d766c7a7b7fc0e0871791b854a6ab6639cc))
- Update deploy.yml ([43714be7684765c7a9fea0a876e8641db30b7ce8](https://github.com/omnixys/omnixys-authentication-service/commit/43714be7684765c7a9fea0a876e8641db30b7ce8))
- Update deploy.yml ([3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f](https://github.com/omnixys/omnixys-authentication-service/commit/3b2dc8cfaa7027eedcc7bd1a5473bc0866afcc2f))
- Update docker-build.yaml ([f07e518267bc05a851dc51ed0356e4f4763f8f69](https://github.com/omnixys/omnixys-authentication-service/commit/f07e518267bc05a851dc51ed0356e4f4763f8f69))
- Update docker-build.yaml ([3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b](https://github.com/omnixys/omnixys-authentication-service/commit/3b62bb3c2a686c54c6519e8a3f8302088a9d3d9b))
- Update docker-build.yaml ([cb09f5619944b5c0a0baa02fc7ab3c213a5a1459](https://github.com/omnixys/omnixys-authentication-service/commit/cb09f5619944b5c0a0baa02fc7ab3c213a5a1459))
- Update docker-build.yaml ([0efb5fe1a38368833fc34e0e2241d0943c93d430](https://github.com/omnixys/omnixys-authentication-service/commit/0efb5fe1a38368833fc34e0e2241d0943c93d430))
- Update docker-build.yaml ([882824b56aa8b62e7a7c21a6dabb95feaafaac6c](https://github.com/omnixys/omnixys-authentication-service/commit/882824b56aa8b62e7a7c21a6dabb95feaafaac6c))
- Update docker-build.yaml ([80a2e9ff207819f30afff727753d783ddb8579eb](https://github.com/omnixys/omnixys-authentication-service/commit/80a2e9ff207819f30afff727753d783ddb8579eb))
- Update docker-build.yaml ([ec717331947801d2a67693cf68ff6dabc5217bcb](https://github.com/omnixys/omnixys-authentication-service/commit/ec717331947801d2a67693cf68ff6dabc5217bcb))
- Update docker-build.yaml ([86febcd4561333f5c4970b2093fae71505c0e508](https://github.com/omnixys/omnixys-authentication-service/commit/86febcd4561333f5c4970b2093fae71505c0e508))
- Update task.yml ([4bf2a920e12ced5818db38df8d2668ac9f326bfe](https://github.com/omnixys/omnixys-authentication-service/commit/4bf2a920e12ced5818db38df8d2668ac9f326bfe))
- update workflow ([56ea0b5be517d7a136f1c19915aaf0f4cb896fa5](https://github.com/omnixys/omnixys-authentication-service/commit/56ea0b5be517d7a136f1c19915aaf0f4cb896fa5))
- breaking(prisma): add MFA ([988e0853fcddecf14678690c64bba772a38188d4](https://github.com/omnixys/omnixys-authentication-service/commit/988e0853fcddecf14678690c64bba772a38188d4))
- chore(setup): initialize NestJS project with modern config and Husky pre-commit hooks ([4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9](https://github.com/omnixys/omnixys-authentication-service/commit/4fdae97f7932c0ab294dc4d4ac73b7dfa3fd8ac9))

## <small>1.0.1 (2025-11-07)</small>

- Initial commit ([135641e](https://github.com/omnixys/omnixys-authentication-service/commit/135641e))

## <small>1.0.1 (2025-11-06)</small>

- chore(dev): integrate custom Commitlint formatter with Husky hook ([1cc0034](https://github.com/omnixys/omnixys-authentication-service/commit/1cc0034))

## 1.0.0 (2025-11-06)

- chore(ci): add GPL-3.0-or-later license header to all GitHub workflow files ([4b5488c](https://github.com/omnixys/omnixys-authentication-service/commit/4b5488c))
- chore(dev): integrate Husky pre-commit and commit-msg hooks for code quality ([261f18f](https://github.com/omnixys/omnixys-authentication-service/commit/261f18f))
- Initial commit ([7c74f0b](https://github.com/omnixys/omnixys-authentication-service/commit/7c74f0b))
- Update CHANGELOG.md ([e8b2951](https://github.com/omnixys/omnixys-authentication-service/commit/e8b2951))
- Update package.json ([f180269](https://github.com/omnixys/omnixys-authentication-service/commit/f180269))
