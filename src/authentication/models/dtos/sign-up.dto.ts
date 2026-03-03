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

import { Field, InputType } from '@nestjs/graphql';
import { PhoneNumberInput } from '@omnixys/graphql';
import { IsEmail, IsString, Length } from 'class-validator';

export interface GuestSignUpDTO {
  invitationId: string;
  seatId?: string;
  eventId: string;
  firstName: string;
  lastName: string;
  pendingContactId?: string | null;
  email?: string;
  phoneNumbers?: PhoneNumberInput[];
  actorId?: string;
}

/**
 * Input type for creating a new user.
 * Corresponds to fields in the User entity.
 */
@InputType()
export class UserSignUpDTO {
  @Field(() => String)
  @IsString()
  @Length(3, 32)
  username!: string;

  @Field(() => String)
  @IsString()
  @Length(1, 64)
  firstName!: string;

  @Field(() => String)
  @IsString()
  @Length(1, 64)
  lastName!: string;

  @Field(() => String)
  @IsEmail()
  email!: string;

  password!: string;
  phoneNumbers?: PhoneNumberInput[];
}
