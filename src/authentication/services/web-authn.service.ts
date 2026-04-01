/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { PrismaService } from '../../prisma/prisma.service.js';
import { Injectable } from '@nestjs/common';
import { ValkeyKey, ValkeyService } from '@omnixys/cache';

import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  generateRegistrationOptions,
  generateAuthenticationOptions,
  type WebAuthnCredential,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
// import { WebAuthnDevicePayload } from '../resolvers/mfa-mutation.resolver.js';

@Injectable()
export class WebAuthnService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: ValkeyService,
  ) {}

  /* =====================================================
     DEVICE MANAGEMENT
  ===================================================== */

  async renameDevice(userId: string, credentialId: string, nickname: string): Promise<boolean> {
    if (!nickname || nickname.length > 50) {
      return false;
    }

    const result = await this.prisma.webAuthnCredential.updateMany({
      where: {
        userId,
        credentialId,
        revokedAt: null,
      },
      data: { nickname },
    });

    return result.count > 0;
  }

  async listDevices(userId: string) {
    return this.prisma.webAuthnCredential.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async revokeDevice(userId: string, credentialId: string): Promise<boolean> {
    const activeDevices = await this.prisma.webAuthnCredential.count({
      where: { userId, revokedAt: null },
    });

    if (activeDevices <= 1) {
      throw new Error('Cannot revoke last active device');
    }

    const result = await this.prisma.webAuthnCredential.updateMany({
      where: {
        userId,
        credentialId,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    });

    return result.count > 0;
  }

  /* =====================================================
     PASSWORDLESS
  ===================================================== */

  async generatePasswordlessOptions(
    email: string,
  ): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
    const user = await this.prisma.authUser.findUnique({
      where: { email },
      include: { webAuthn: true },
    });

    if (!user || user.webAuthn.length === 0) {
      // prevent enumeration
      return null;
    }

    const options = await this.generateAuthOptions(user.id);
    return options;
  }

  async verifyPasswordlessAuthentication(
    response: AuthenticationResponseJSON,
  ): Promise<string | null> {
    const credential = await this.prisma.webAuthnCredential.findUnique({
      where: { credentialId: response.id },
      include: { user: true },
    });

    if (!credential || credential.revokedAt) {
      return null;
    }

    const ok = await this.verifyAuthenticationForUser(credential.userId, response);

    if (!ok) {
      return null;
    }

    return credential.userId;
  }

  async generateDiscoverableAuthOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const options = await generateAuthenticationOptions({
      rpID: process.env.WEBAUTHN_RP_ID!,
      userVerification: 'required',
      // 🚀 no allowCredentials → discoverable credentials
    });

    // Challenge global speichern
    await this.cache.set(
      ValkeyKey.webauthnGlobalAuthChallenge,
      {
        challenge: options.challenge,
      },
      5 * 60,
    );

    return options;
  }

  async verifyDiscoverableAuthentication(
    response: AuthenticationResponseJSON,
  ): Promise<string | null> {
    if (!response?.id) {
      return null;
    }

    const clientData = JSON.parse(
      Buffer.from(response.response.clientDataJSON, 'base64url').toString(),
    );

    const challenge = clientData.challenge;
    if (!challenge) {
      return null;
    }

    const expectedChallenge = await this.cache.get(
      ValkeyKey.webauthnGlobalAuthChallenge,
      challenge,
    );

    if (!expectedChallenge) {
      return null;
    }

    // Besser: Challenge separat speichern – siehe unten

    const credentialRecord = await this.prisma.webAuthnCredential.findUnique({
      where: { credentialId: response.id },
      include: { user: true },
    });

    if (!credentialRecord || credentialRecord.revokedAt) {
      return null;
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN!,
      expectedRPID: process.env.WEBAUTHN_RP_ID!,
      credential: {
        id: credentialRecord.credentialId,
        publicKey: new Uint8Array(Buffer.from(credentialRecord.publicKey, 'base64url')),
        counter: credentialRecord.counter,
      },
    });

    if (!verification.verified) {
      return null;
    }

    await this.prisma.webAuthnCredential.update({
      where: { id: credentialRecord.id },
      data: {
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      },
    });

    await this.cache.delete(ValkeyKey.webauthnGlobalAuthChallenge, challenge);

    return credentialRecord.userId;
  }

  /* =======================================================
     AUTHENTICATION VERIFY
  ======================================================= */

  async verifyAuthenticationForUser(
    userId: string,
    response: AuthenticationResponseJSON,
  ): Promise<boolean> {
    const expectedChallenge = await this.getAuthenticationChallenge(userId);

    if (!expectedChallenge) {
      return false;
    }
    if (!response?.id) {
      return false;
    }

    const credentialRecord = await this.prisma.webAuthnCredential.findFirst({
      where: { userId, credentialId: response.id, revokedAt: null },
    });

    if (!credentialRecord) {
      return false;
    }

    const credential: WebAuthnCredential = {
      id: credentialRecord.credentialId,
      publicKey: new Uint8Array(Buffer.from(credentialRecord.publicKey, 'base64url')),
      counter: credentialRecord.counter,
      transports: credentialRecord.transports
        ? (credentialRecord.transports.split(',') as any)
        : undefined,
    };

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN!,
      expectedRPID: process.env.WEBAUTHN_RP_ID!,
      credential,
    });

    if (!verification.verified) {
      return false;
    }

    await this.prisma.webAuthnCredential.update({
      where: { id: credentialRecord.id },
      data: {
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      },
    });

    await this.prisma.webAuthnCredential.update({
      where: { id: credentialRecord.id },
      data: { counter: verification.authenticationInfo.newCounter },
    });

    await this.consumeAuthenticationChallenge(userId);

    return true;
  }

  /* =======================================================
     REGISTRATION OPTIONS
  ======================================================= */

  async generateOptions(
    userId: string,
    email: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const userCredentials = await this.prisma.webAuthnCredential.findMany({
      where: { userId, revokedAt: null },
    });

    const options = await generateRegistrationOptions({
      rpName: 'Omnixys',
      rpID: process.env.WEBAUTHN_RP_ID!,
      userID: new TextEncoder().encode(userId),
      userName: email,
      attestationType: 'none',
      excludeCredentials: userCredentials.map((c) => ({
        id: c.credentialId,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    await this.storeRegistrationChallenge(userId, options.challenge);

    return options;
  }

  /* =======================================================
     REGISTRATION VERIFY
  ======================================================= */

  async verifyRegistration(userId: string, response: RegistrationResponseJSON): Promise<boolean> {
    const expectedChallenge = await this.getRegistrationChallenge(userId);

    if (!expectedChallenge) {
      return false;
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: process.env.WEBAUTHN_ORIGIN!,
      expectedRPID: process.env.WEBAUTHN_RP_ID!,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return false;
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    await this.prisma.webAuthnCredential.create({
      data: {
        credentialId: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        userId,
      },
    });

    await this.cache.delete(ValkeyKey.webauthnRegChallenge, userId);

    return true;
  }

  /* =======================================================
     AUTH OPTIONS
  ======================================================= */

  async generateAuthOptions(userId: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const credentials = await this.prisma.webAuthnCredential.findMany({
      where: { userId, revokedAt: null },
    });

    const options = await generateAuthenticationOptions({
      rpID: process.env.WEBAUTHN_RP_ID!,
      allowCredentials: credentials.map((c) => ({
        id: c.credentialId,
      })),
      userVerification: 'required',
    });

    await this.storeAuthenticationChallenge(userId, options.challenge);

    return options;
  }

  /* =======================================================
     CHALLENGE STORE (VALKEY)
  ======================================================= */
  async storeRegistrationChallenge(userId: string, challenge: string): Promise<string> {
    return this.cache.set(ValkeyKey.webauthnRegChallenge, { userId, challenge }, 5 * 60);
  }

  async getRegistrationChallenge(userId: string): Promise<string | null> {
    return this.cache.get(ValkeyKey.webauthnRegChallenge, userId);
  }

  async storeAuthenticationChallenge(userId: string, challenge: string): Promise<string> {
    return this.cache.set(ValkeyKey.webauthnAuthChallenge, { challenge, userId }, 5 * 60);
  }

  async getAuthenticationChallenge(userId: string): Promise<string | null> {
    return this.cache.get(ValkeyKey.webauthnAuthChallenge, userId);
  }

  async consumeAuthenticationChallenge(userId: string): Promise<void> {
    await this.cache.delete(ValkeyKey.webauthnAuthChallenge, userId);
  }
}
