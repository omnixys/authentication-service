/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { OAuthService } from '../services/o-auth.service.js';
import { Controller, Get, Param, Query, BadRequestException, Res } from '@nestjs/common';
import { FastifyReply } from 'fastify';

const isProd = process.env.NODE_ENV === 'production';

@Controller('auth/oauth')
export class OAuthController {
  constructor(private readonly oauthService: OAuthService) {}

  /* =====================================================
     STEP 1 – Redirect to Provider
  ===================================================== */
  @Get(':provider')
  async redirect(@Param('provider') provider: string, @Res() reply: FastifyReply) {
    if (!['github', 'google'].includes(provider)) {
      throw new BadRequestException('Unsupported provider');
    }

    const { url } = await this.oauthService.getAuthUrl(provider);

    reply.status(302).redirect(url);
  }

  /* =====================================================
     STEP 2 – Callback
  ===================================================== */
  @Get(':provider/callback')
  async callback(
    @Param('provider') provider: string,
    @Res() reply: FastifyReply,
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('error') error?: string,
  ) {
    if (error) {
      return reply.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }

    if (!code || !state) {
      throw new BadRequestException('Missing OAuth parameters');
    }

    const token = await this.oauthService.handleCallback(provider, code, state);
    /* -----------------------------
       Cookie setzen (Fastify!)
    ----------------------------- */
    reply.setCookie('access_token', token.accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'lax' : 'lax',
      path: '/',
      maxAge: token.expiresIn,
    });

    reply.setCookie('refresh_token', token.refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'lax' : 'lax',
      path: '/',
      maxAge: token.refreshExpiresIn,
    });

    reply.status(302).redirect(`http://localhost:3000/home`);
  }
}
