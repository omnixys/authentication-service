/* eslint-disable @typescript-eslint/explicit-function-return-type */
import {
  Resolver,
  Mutation,
  Args,
  Field,
  ObjectType,
  Query,
} from '@nestjs/graphql';

import {
  BadRequestException,
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';

import { BackupCodeService } from '../services/backup-code.service.js';
import { TotpService } from '../services/totp.service.js';
import { WebAuthnService } from '../services/web-authn.service.js';

import {
  CurrentUser,
  CurrentUserData,
} from '../../auth/decorators/current-user.decorator.js';
import { CookieAuthGuard } from '../../auth/guards/cookie-auth.guard.js';
import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { MfaPreference } from '../models/dtos/reset-verification-result.dto.js';
import { SecurityQuestionMapper } from '../models/mappers/security-question.mapper.js';
import { TotpSetupPayload } from '../models/payloads/mfa.types.js';
import { SecurityQuestionPayload } from '../models/payloads/security-question.payload.js';
import { SecurityQuestionService } from '../services/security-question.service.js';
import {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

@ObjectType()
export class WebAuthnDevicePayload {
  @Field()
  credentialId!: string;

  @Field({ nullable: true })
  nickname?: string;

  @Field()
  deviceType!: string;

  @Field()
  backedUp!: boolean;

  @Field()
  createdAt!: Date;

  @Field({ nullable: true })
  lastUsedAt?: Date;

  @Field({ nullable: true })
  revokedAt?: Date;
}

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class MfaMutationResolver {
  constructor(
    private readonly totpService: TotpService,
    private readonly webAuthnService: WebAuthnService,
    private readonly backupCodeService: BackupCodeService,
    private readonly prisma: PrismaService,
    private readonly securityQuestionService: SecurityQuestionService,
  ) {}

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async setMfaPreference(
    @CurrentUser() user: CurrentUserData,
    @Args('method', { type: () => MfaPreference })
    method: MfaPreference,
  ): Promise<boolean> {
    await this.prisma.authUser.update({
      where: { id: user.id },
      data: { mfaPreference: method },
    });

    return true;
  }

  @UseGuards(CookieAuthGuard)
  @Query(() => [WebAuthnDevicePayload])
  async listWebAuthnDevices(@CurrentUser() currentUser: CurrentUserData) {
    // : Promise<WebAuthnDevicePayload[]>
    const userId = currentUser.id;

    return this.webAuthnService.listDevices(userId);
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async revokeWebAuthnCredential(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('credentialId') credentialId: string,
  ): Promise<boolean> {
    const userId = currentUser.id;

    if (!credentialId) {
      throw new BadRequestException('Missing credentialId');
    }

    const ok = await this.webAuthnService.revokeDevice(userId, credentialId);

    if (!ok) {
      throw new UnauthorizedException('Device not found or already revoked');
    }

    return true;
  }

  /* =======================================================
     TOTP
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => TotpSetupPayload)
  async enableTotp(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<TotpSetupPayload> {
    const userId = currentUser.id;
    const email = currentUser.email;

    return this.totpService.generateForUser(userId, email);
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async confirmTotp(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('code') code: string,
  ): Promise<boolean> {
    const userId = currentUser.id;

    return this.totpService.enable(userId, code);
  }

  /* =======================================================
     WEBAUTHN REGISTRATION
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => JsonScalar)
  async generateWebAuthnRegistrationOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;
    const email = currentUser.email;

    const options = await this.webAuthnService.generateOptions(userId, email);

    return options;
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async verifyWebAuthnRegistration(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response') response: JsonScalar,
  ): Promise<boolean> {
    const userId = currentUser.id;

    return this.webAuthnService.verifyRegistration(
      userId,
      response as unknown as RegistrationResponseJSON,
    );
  }

  /* =======================================================
     WEBAUTHN AUTHENTICATION (Step-up / Login verification)
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => JsonScalar, { name: 'generateWebAuthnAuthOptions2' })
  async generateWebAuthnAuthOptions(
    @CurrentUser() currentUser: CurrentUserData,
  ) {
    const userId = currentUser.id;

    // Generates challenge + allowCredentials and stores challenge in Valkey (inside service).
    return this.webAuthnService.generateAuthOptions(userId);
  }

  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean, { name: 'verifyWebAuthnAuthentication2' })
  async verifyWebAuthnAuthentication(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('response', { type: () => JsonScalar }) response: unknown,
  ): Promise<boolean> {
    const userId = currentUser.id;

    if (!response || typeof response !== 'object') {
      throw new BadRequestException('Invalid WebAuthn response');
    }

    const ok = await this.webAuthnService.verifyAuthenticationForUser(
      userId,
      response as AuthenticationResponseJSON,
    );

    if (!ok) {
      throw new UnauthorizedException('WebAuthn verification failed');
    }

    return true;
  }

  /* =======================================================
     BACKUP CODES
  ======================================================= */

  @UseGuards(CookieAuthGuard)
  @Mutation(() => [String])
  async regenerateBackupCodes(
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<string[]> {
    const userId = currentUser.id;

    return this.backupCodeService.generate(userId);
  }

  /* =====================================================
   DEVICE RENAME
===================================================== */
  @UseGuards(CookieAuthGuard)
  @Mutation(() => Boolean)
  async renameWebAuthnCredential(
    @CurrentUser() currentUser: CurrentUserData,
    @Args('credentialId') credentialId: string,
    @Args('nickname') nickname: string,
  ): Promise<boolean> {
    const ok = await this.webAuthnService.renameDevice(
      currentUser.id,
      credentialId,
      nickname,
    );

    if (!ok) {
      throw new BadRequestException('Rename failed');
    }

    return true;
  }

  @Query(() => [SecurityQuestionPayload])
  async getSecurityQuestions(): Promise<SecurityQuestionPayload[]> {
    const securityQuestions =
      await this.securityQuestionService.getAllQuestions();
    return securityQuestions
      ? SecurityQuestionMapper.toPayloadList(securityQuestions)
      : [];
  }
}
