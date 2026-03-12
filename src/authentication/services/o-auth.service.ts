/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/explicit-function-return-type */

import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { PrismaService } from '../../prisma/prisma.service.js';
import { TraceContextProvider } from '../../trace/trace-context.provider.js';
import { ValkeyService } from '../../valkey/valkey.service.js';
import { AuthWriteService } from './authentication-write.service.js';
import { AuthenticateBaseService } from './keycloak-base.service.js';
import { UserWriteService } from './user-write.service.js';
import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';

/* =========================================================
   TYPE DEFINITIONS
========================================================= */

interface GithubTokenResponse {
  access_token: string;
  token_type: string;
  scope: string;
}

interface GithubUser {
  id: number;
  email: string | null;
  name: string | null;
}

interface GithubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

interface GoogleTokenResponse {
  access_token: string;
}

interface GoogleUser {
  sub: string;
  email: string;
  name: string;
}

/* =========================================================
   OAUTH SERVICE
========================================================= */

@Injectable()
export class OAuthService extends AuthenticateBaseService {
  constructor(
    logger: LoggerPlusService,
    trace: TraceContextProvider,
    http: HttpService,
    private readonly prisma: PrismaService,
    private readonly authService: AuthWriteService,
    private readonly valkey: ValkeyService,
    private readonly userWriteService: UserWriteService,
  ) {
    super(logger, trace, http);
  }

  /* =====================================================
     STEP 1 – Generate Redirect URL + Store State
  ===================================================== */

  async getAuthUrl(provider: string): Promise<{ url: string }> {
    const state = crypto.randomUUID();

    await this.valkey.client.set(
      `oauth:state:${state}`,
      provider,
      { PX: 5 * 60 * 1000 }, // 5 min TTL
    );

    if (provider === 'github') {
      return {
        url: `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${process.env.GITHUB_REDIRECT_URI}&scope=user:email&state=${state}`,
      };
    }

    if (provider === 'google') {
      return {
        url: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.GOOGLE_REDIRECT_URI}&response_type=code&scope=openid%20email%20profile&state=${state}`,
      };
    }

    throw new BadRequestException('Unsupported OAuth provider');
  }

  /* =====================================================
     STEP 2 – Handle Callback + Validate State
  ===================================================== */

  async handleCallback(provider: string, code: string, state: string) {
    const stored = await this.valkey.client.get(`oauth:state:${state}`);

    if (!stored || stored !== provider) {
      throw new UnauthorizedException('Invalid OAuth state');
    }

    await this.valkey.client.del(`oauth:state:${state}`);

    if (provider === 'github') {
      return this.handleGithub(code);
    }

    if (provider === 'google') {
      return this.handleGoogle(code);
    }

    if (!['github', 'google'].includes(provider)) {
      throw new BadRequestException('Unsupported provider');
    }

    throw new BadRequestException('Unsupported OAuth provider');
  }

  /* =====================================================
     GITHUB FLOW
  ===================================================== */

  private async handleGithub(code: string) {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: new URLSearchParams({
        client_id: process.env.GITHUB_CLIENT_ID!,
        client_secret: process.env.GITHUB_CLIENT_SECRET!,
        code,
      }),
    });

    if (!tokenRes.ok) {
      throw new UnauthorizedException('GitHub token exchange failed');
    }

    const tokenData = (await tokenRes.json()) as GithubTokenResponse;

    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    if (!userRes.ok) {
      throw new UnauthorizedException('GitHub user fetch failed');
    }

    const githubUser = (await userRes.json()) as GithubUser;

    let email = githubUser.email;

    // GitHub may not return email in /user
    if (!email) {
      const emailRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      });

      if (!emailRes.ok) {
        throw new UnauthorizedException('GitHub email fetch failed');
      }

      const emails = (await emailRes.json()) as GithubEmail[];
      const primary = emails.find((e) => e.primary && e.verified);
      email = primary?.email ?? null;
    }

    if (!email) {
      throw new UnauthorizedException('No verified GitHub email found');
    }

    const user = await this.findOrCreateUser({
      provider: 'github',
      providerId: String(githubUser.id),
      email,
      name: githubUser.name ?? undefined,
    });

    return this.authService.createPasswordlessSession(user.id);
  }

  /* =====================================================
     GOOGLE FLOW
  ===================================================== */

  private async handleGoogle(code: string) {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID!,
        client_secret: process.env.GOOGLE_CLIENT_SECRET!,
        code,
        grant_type: 'authorization_code',
        redirect_uri: process.env.GOOGLE_REDIRECT_URI!,
      }),
    });

    if (!tokenRes.ok) {
      throw new UnauthorizedException('Google token exchange failed');
    }

    const tokenData = (await tokenRes.json()) as GoogleTokenResponse;

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    if (!profileRes.ok) {
      throw new UnauthorizedException('Google profile fetch failed');
    }

    const googleUser = (await profileRes.json()) as GoogleUser;

    const user = await this.findOrCreateUser({
      provider: 'google',
      providerId: googleUser.sub,
      email: googleUser.email,
      name: googleUser.name,
    });

    return this.authService.createPasswordlessSession(user.id);
  }

  /* =====================================================
     FIND OR CREATE USER + ACCOUNT LINKING
  ===================================================== */

  private async findOrCreateUser(data: {
    provider: string;
    providerId: string;
    email: string;
    name?: string;
  }) {
    // 1️⃣ Check existing OAuth account
    let user = await this.prisma.authUser.findFirst({
      where: {
        oauthAccounts: {
          some: {
            provider: data.provider,
            providerId: data.providerId,
          },
        },
      },
    });

    if (user) {
      return user;
    }

    // 2️⃣ Account linking by email
    user = await this.prisma.authUser.findUnique({
      where: { email: data.email },
    });

    if (user) {
      await this.prisma.oAuthAccount.create({
        data: {
          provider: data.provider,
          providerId: data.providerId,
          userId: user.id,
        },
      });

      return user;
    }

    const userId = await this.userWriteService.createKeycloakUser(data);
    user = await this.prisma.authUser.create({
      data: {
        id: userId,
        email: data.email,
        username: data.name ?? '',
        oauthAccounts: {
          create: {
            provider: data.provider,
            providerId: data.providerId,
          },
        },
      },
    });

    return user;
  }
}
