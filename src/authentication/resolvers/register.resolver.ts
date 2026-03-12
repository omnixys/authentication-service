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

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';
import { SignUpPayload } from '../models/payloads/sign-in.payload.js';
import { RegisterService } from '../services/register.service.js';
import { UseInterceptors } from '@nestjs/common';
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { GqlFastifyContext, gqlSetTokens } from '@omnixys/context';

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class RegisterResolver {
  private readonly logger = getLogger(RegisterResolver.name);

  constructor(private readonly registerService: RegisterService) {}

  @Mutation(() => SignUpPayload)
  async verifySignUp(
    @Args('token') token: string,
    @Context() ctx: GqlFastifyContext,
  ): Promise<SignUpPayload> {
    this.logger.debug('Verify Registration');
    const payload = await this.registerService.verifySignup(token);
    const res = ctx.reply;

    gqlSetTokens(
      res,
      payload?.token?.accessToken ?? '',
      payload?.token?.expiresIn ?? 0 * 1000,
    );

    return payload;
  }
}
