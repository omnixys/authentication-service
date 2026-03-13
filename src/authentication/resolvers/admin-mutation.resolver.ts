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

import { UseInterceptors } from '@nestjs/common';
import { Args, Context, ID, Mutation, Resolver } from '@nestjs/graphql';

import { getLogger } from '../../logger/get-logger.js';
import { ResponseTimeInterceptor } from '../../logger/response-time.interceptor.js';

import { AdminSignUpInput } from '../models/inputs/sign-up.input.js';
import {
  UpdateKcUserInput,
  UpdateUserPasswordInput,
} from '../models/inputs/update-user.input.js';
import { TokenPayload } from '../models/payloads/token.payload.js';
import { AdminWriteService } from '../services/admin-write.service.js';
import { GqlFastifyContext, gqlSetTokens } from '@omnixys/context';
import { RealmRoleType } from '@omnixys/contracts';

/**
 * @fileoverview
 * GraphQL resolver providing **administrative mutations** for managing users and roles.
 *
 * @remarks
 * Exposes operations for:
 * - User profile updates (`adminUpdateUser`)
 * - Password management (`adminChangePassword`)
 * - User deletion (`deleteUser`)
 * - Role assignment and removal (`assignRealmRole`, `removeRealmRole`)
 *
 * All endpoints are decorated with `@Public()` but should be protected by Keycloak
 * realm roles (`ADMIN`) in production environments.
 */
@Resolver()
@UseInterceptors(ResponseTimeInterceptor)
export class AdminMutationResolver {
  /** Internal logger instance used for diagnostic output. */
  private readonly logger = getLogger(AdminMutationResolver.name);

  /**
   * Constructs an {@link AdminMutationResolver}.
   *
   * @param adminService - Service responsible for performing user and role write operations.
   */
  constructor(private readonly adminService: AdminWriteService) {}

  // ---------------------------------------------------------------------------
  // 🧩 User Management
  // ---------------------------------------------------------------------------

  /**
   * Updates user profile fields such as first name, last name, and email.
   *
   * @mutation adminUpdateUser
   * @public
   *
   * @param id - The unique Keycloak user ID.
   * @param input - The {@link UpdateKcUserInput} containing profile changes.
   * @returns A boolean value indicating whether the update was successful.
   */
  @Mutation(() => Boolean, { name: 'adminUpdateUser' })
  async updateUser(
    @Args('id', { type: () => ID }) id: string,
    @Args('input', { type: () => UpdateKcUserInput }) input: UpdateKcUserInput,
  ): Promise<boolean> {
    this.logger.debug('adminUpdateUser: id=%s', id);
    await this.adminService.updateUser(id, input);
    return true;
  }

  /**
   * Sets a new password for a given user.
   *
   * @remarks
   * This method replaces the existing password with a new permanent one.
   * It is not used for temporary or reset tokens.
   *
   * @mutation adminChangePassword
   * @public
   *
   * @param input - Contains the user ID and the new password value.
   * @returns A boolean value indicating whether the password was updated successfully.
   */
  @Mutation(() => Boolean, { name: 'adminChangePassword' })
  async changeUserPassword(
    @Args('input', { type: () => UpdateUserPasswordInput })
    input: UpdateUserPasswordInput,
  ): Promise<boolean> {
    await this.adminService.setUserPassword(input.id, input.newPassword);
    return true;
  }

  /**
   * Permanently deletes a user from the Keycloak realm.
   *
   * @mutation deleteUser
   * @public
   *
   * @param id - The unique Keycloak user ID to delete.
   * @returns A boolean value indicating whether the user was deleted successfully.
   */
  @Mutation(() => Boolean, { name: 'deleteKcUser' })
  async deleteUser(
    @Args('id', { type: () => ID }) id: string,
  ): Promise<boolean> {
    await this.adminService.deleteUser(id);
    return true;
  }

  // ---------------------------------------------------------------------------
  // 🔐 Role Management
  // ---------------------------------------------------------------------------

  /**
   * Assigns a realm role to a specific user.
   *
   * @mutation assignRealmRole
   * @protected
   *
   * @param id - The unique Keycloak user ID.
   * @param roleName - The {@link RealmRoleType} enum representing the role to assign.
   * @returns A boolean value indicating whether the role was successfully assigned.
   */
  @Mutation(() => Boolean, { name: 'assignRealmRole' })
  async assignRealmRole(
    @Args('id', { type: () => ID }) id: string,
    @Args('roleName', { type: () => RealmRoleType }) roleName: RealmRoleType,
  ): Promise<boolean> {
    this.logger.debug('assignRealmRole: userId=%s, role=%s', id, roleName);
    await this.adminService.assignRealmRoleToUser(id, roleName);
    return true;
  }

  /**
   * Removes a previously assigned realm role from a user.
   *
   * @mutation removeRealmRole
   * @protected
   *
   * @param id - The unique Keycloak user ID.
   * @param roleName - The {@link RealmRoleType} enum representing the role to remove.
   * @returns A boolean value indicating whether the role was successfully removed.
   */
  @Mutation(() => Boolean, { name: 'removeRealmRole' })
  async removeRealmRole(
    @Args('id', { type: () => ID }) id: string,
    @Args('roleName', { type: () => RealmRoleType }) roleName: RealmRoleType,
  ): Promise<boolean> {
    this.logger.debug('removeRealmRole: userId=%s, role=%s', id, roleName);
    await this.adminService.removeRealmRoleFromUser(id, roleName);
    return true;
  }

  @Mutation(() => TokenPayload, { name: 'adminSignUp' })
  async adminSignIn(
    @Args('input', { type: () => AdminSignUpInput }) input: AdminSignUpInput,
    @Context() ctx: GqlFastifyContext,
  ): Promise<TokenPayload> {
    this.logger.debug('signIn: input=%o', input);
    const result = await this.adminService.adminSignUp(input);
    const res = ctx.reply;
    gqlSetTokens(res, result.accessToken, result.expiresIn * 1000);
    return result;
  }
}
