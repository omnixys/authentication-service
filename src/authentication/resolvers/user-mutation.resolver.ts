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
import { UserSignUpInput } from '../models/inputs/sign-up.input.js';
import { ChangeMyPasswordInput } from '../models/inputs/update-password.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { UserWriteService } from '../services/user-write.service.js';
import {
  UnauthorizedException,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { CookieAuthGuard, CurrentUser, CurrentUserData } from '@omnixys/auth';
import { GqlFastifyContext, gqlSetTokens } from '@omnixys/context';

@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class UserMutationResolver {
  private readonly logger = getLogger(UserMutationResolver.name);

  constructor(private readonly userService: UserWriteService) {}

  @Mutation(() => SuccessPayload)
  @UseGuards(CookieAuthGuard)
  async changeMyPassword(
    @Args('input') input: ChangeMyPasswordInput,
    @CurrentUser() user: CurrentUserData,
  ): Promise<SuccessPayload> {
    if (!user?.id) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    const username = user?.username ?? user?.username;
    this.logger.debug('changeMyPassword: id=%s', user?.id);

    // this.logger.debug('changeMyPassword: user=%o', user);

    await this.userService.changePassword({
      userId: user.id,
      username,
      oldPassword: input.oldPassword,
      newPassword: input.newPassword,
    });

    return { ok: true, message: 'Password updated' };
  }

  @Mutation(() => SuccessPayload)
  @UseGuards(CookieAuthGuard)
  async updateMyProfile(
    @Args('input') input: UpdateMyProfileInput,
    @CurrentUser() currentUser: CurrentUserData,
  ): Promise<{ ok: boolean; message: string }> {
    if (!currentUser?.id) {
      // Kein authentifizierter Nutzer im Kontext
      throw new UnauthorizedException('Not authenticated');
    }

    await this.userService.update(currentUser.id, input);
    return { ok: true, message: 'Profile updated' };
  }

  @Mutation(() => TokenPayload, { name: 'userSignUp' })
  async userSignIn(
    @Args('input', { type: () => UserSignUpInput }) input: UserSignUpInput,
    @Context() ctx: GqlFastifyContext,
  ): Promise<TokenPayload> {
    this.logger.debug('signIn: input=%o', input);
    const result = await this.userService.userSignUp(input);
    const res = ctx?.reply;

    gqlSetTokens(res, result.accessToken, result.expiresIn * 1000);

    return result;
  }

  // @Mutation(() => SignUpPayload, { name: 'guestSignUp' })
  // async guestSignIn(
  //   @Args('input', { type: () => GuestSignUpInput }) input: GuestSignUpInput,
  // ): Promise<SignUpPayload> {
  //   this.logger.debug('signIn: input=%o', input);
  //   const result = await this.userService.guestSignUp(input);
  //   return result;
  // }
}
