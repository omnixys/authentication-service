/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import { CoreHttpModule } from '../http.module.js';
import { KafkaModule } from '../kafka/kafka.module.js';
import { LoggerModule } from '../logger/logger.module.js';
import { PrismaModule } from '../prisma/prisma.module.js';
import { TraceModule } from '../trace/trace.module.js';
import { ValkeyModule } from '../valkey/valkey.module.js';
import { OAuthController } from './controllers/o-auth.controller.js';
import { AdminMutationResolver } from './resolvers/admin-mutation.resolver.js';
import { AuthMutationResolver } from './resolvers/authentication-mutation.resolver.js';
import { AuthQueryResolver } from './resolvers/authentication-query.resolver.js';
import { DebugResolver } from './resolvers/debug.resolver.js';
import { MfaMutationResolver } from './resolvers/mfa-mutation.resolver.js';
import { RegisterResolver } from './resolvers/register.resolver.js';
import { ResetMutationResolver } from './resolvers/reset-mutation.resolver.js';
import { UserMutationResolver } from './resolvers/user-mutation.resolver.js';
import { AdminWriteService } from './services/admin-write.service.js';
import { Argon2Service } from './services/argon2.service.js';
import { AuthWriteService } from './services/authentication-write.service.js';
import { BackupCodeService } from './services/backup-code.service.js';
import { DeviceService } from './services/device.service.js';
import { EncryptionService } from './services/encryption.service.js';
import { GeoIpService } from './services/geoip.service.js';
import { HmacService } from './services/hmac.service.js';
import { LockoutService } from './services/lockout.service.js';
import { OAuthService } from './services/o-auth.service.js';
import { PendingContactService } from './services/pending-contact.service.js';
import { AuthenticateReadService } from './services/read.service.js';
import { RegisterService } from './services/register.service.js';
import { ResetService } from './services/reset.service.js';
import { RiskEngineService } from './services/risk-engine.service.js';
import { SecurityQuestionService } from './services/security-question.service.js';
import { TotpService } from './services/totp.service.js';
import { UserWriteService } from './services/user-write.service.js';
import { WebAuthnService } from './services/web-authn.service.js';
import { Module } from '@nestjs/common';
import { AuthModule } from '@omnixys/auth';

@Module({
  imports: [
    KafkaModule,
    LoggerModule,
    TraceModule,
    CoreHttpModule,
    AuthModule,
    ValkeyModule,
    PrismaModule,
  ],
  controllers: [OAuthController],
  providers: [
    AuthQueryResolver,
    AuthMutationResolver,
    UserMutationResolver,
    AdminMutationResolver,
    PendingContactService,
    MfaMutationResolver,
    ResetMutationResolver,
    RegisterResolver,
    DebugResolver,

    AuthenticateReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
    RegisterService,
    TotpService,
    WebAuthnService,
    BackupCodeService,
    ResetService,
    EncryptionService,
    Argon2Service,
    LockoutService,
    HmacService,
    SecurityQuestionService,
    RiskEngineService,
    GeoIpService,
    DeviceService,
    OAuthService,
  ],
  exports: [
    AuthenticateReadService,
    UserWriteService,
    AdminWriteService,
    AuthWriteService,
    PendingContactService,
    RegisterService,
  ],
})
export class AuthenticationModule {}
