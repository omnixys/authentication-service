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
import { ChangeMyPasswordInput } from '../models/inputs/update-password.input.js';
import { UpdateMyProfileInput } from '../models/inputs/user-update.input.js';
import { GuestSignUpPayload } from '../models/payloads/sign-in.payload.js';
import { SuccessPayload } from '../models/payloads/success.payload.js';
import { UserWriteService } from '../services/user-write.service.js';
import { UseGuards } from '@nestjs/common';
import { Args, Mutation, Resolver } from '@nestjs/graphql';
import { ClientInfo, type ClientContext } from '@omnixys/context';
import { OmnixysLogger } from '@omnixys/logger';
import { TraceRunner } from '@omnixys/observability';
import {
  CookieAuthGuard,
  CurrentUser,
  CurrentUserData,
  InvalidCredentialsException,
} from '@omnixys/security';

@Resolver()
export class UserMutationResolver {
  private readonly log;

  constructor(
    private readonly userService: UserWriteService,
    omnixysLogger: OmnixysLogger,
  ) {
    this.log = omnixysLogger.log(this.constructor.name);
  }

  @Mutation(() => SuccessPayload)
  @UseGuards(CookieAuthGuard)
  async changeMyPassword(
    @Args('input') input: ChangeMyPasswordInput,
    @CurrentUser() user: CurrentUserData,
  ): Promise<SuccessPayload> {
    if (!user?.id) {
      // Kein authentifizierter Nutzer im Kontext
      throw new InvalidCredentialsException('Not authenticated');
    }

    const username = user?.username ?? user?.username;
    this.log.debug('changeMyPassword: id=%s', user?.id);

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
      throw new InvalidCredentialsException('Not authenticated');
    }

    await this.userService.update(currentUser.id, input);
    return { ok: true, message: 'Profile updated' };
  }

  @Mutation(() => GuestSignUpPayload, { name: 'verifyGuestSignUp' })
  async verifyGuestSignUp(
    @Args('token') token: string,
    @ClientInfo() clientInfo: ClientContext,
  ): Promise<GuestSignUpPayload> {
    return TraceRunner.run(
      '[RESOLVER] Verify Guest SignUp',
      async (): Promise<GuestSignUpPayload> => {
        this.log.debug('Guest sign-up verification requested');
        const result = await this.userService.guestSignUp(token, clientInfo);
        return {
          message: result.message,
          results: result.users,
        };
      },
    );
  }
}
