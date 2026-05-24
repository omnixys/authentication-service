# 🧾 Changelog

All notable changes in this project will be documented in this file.


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
