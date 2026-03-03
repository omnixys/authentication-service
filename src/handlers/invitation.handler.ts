/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-explicit-any */

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
import { GuestSignUpDTO } from '../authentication/models/dtos/sign-up.dto.js';
import { PhoneNumberType } from '../authentication/models/enums/phone-number-type.enum.js';
import { PendingContactService } from '../authentication/services/pending-contact.service.js';
import { UserWriteService } from '../authentication/services/user-write.service.js';
import {
  KafkaEvent,
  KafkaHandler,
} from '../kafka/decorators/kafka-event.decorator.js';
import {
  type KafkaEventContext,
  KafkaEventHandler,
} from '../kafka/interface/kafka-event.interface.js';
import { getTopic, getTopics } from '../kafka/kafka-topic.properties.js';
import { LoggerPlusService } from '../logger/logger-plus.service.js';
import { Injectable } from '@nestjs/common';
import { PhoneNumberInput } from '@omnixys/graphql';

/**
 * Kafka event handler responsible for useristrative commands such as
 * shutdown and restart. It listens for specific user-related topics
 * and delegates the actual process control logic to the {@link UserService}.
 *
 * @category kafka
 * @since 1.0.0
 */
@KafkaHandler('invitation')
@Injectable()
export class InvitationHandler implements KafkaEventHandler {
  private readonly logger;

  /**
   * Creates a new instance of {@link UserHandler}.
   *
   * @param loggerService - The central logger service used for structured logging.
   * @param userService - The service responsible for handling system-level user operations.
   */
  constructor(
    private readonly loggerService: LoggerPlusService,
    private readonly userWriteService: UserWriteService,
    private readonly pendingService: PendingContactService,
  ) {
    this.logger = this.loggerService.getLogger(InvitationHandler.name);
  }

  /**
   * Handles incoming Kafka user events and executes the appropriate useristrative command.
   *
   * @param topic - The Kafka topic representing the user command (e.g. shutdown, restart).
   * @param data - The payload associated with the Kafka message.
   * @param context - The Kafka context metadata containing headers and partition info.
   *
   * @returns A Promise that resolves once the command has been processed.
   */
  @KafkaEvent(...getTopics('createGuest'))
  async handle(
    topic: string,
    data: any,
    context: KafkaEventContext,
  ): Promise<void> {
    this.logger.warn(`User command received: ${topic}`);
    this.logger.debug('Kafka context: %o', context);
    this.logger.debug('Kafka message: %o', data);

    switch (topic) {
      case getTopic('createGuest'):
        await this.createGuest(data);
        break;

      default:
        this.logger.warn(`Unknown user topic: ${topic}`);
    }
  }

  private async createGuest(data: { payload: GuestSignUpDTO }): Promise<void> {
    this.logger.debug('CreateUserHandler: data=%o', data);
    let email: string | undefined;
    let phoneNumbers: PhoneNumberInput[] | undefined;

    const { pendingContactId, invitationId } = data.payload;
    if (pendingContactId) {
      const pc = await this.pendingService.get(pendingContactId);
      if (pc) {
        email = pc.email;
        // PendingContactService speichert `phones`
        phoneNumbers = await this.normalizePhones(pc?.phoneNumbers);
        await this.pendingService.delete(pendingContactId).catch(() => void 0);
      } else {
        this.logger.warn(
          'pending contact missing for invitation=%s (TTL abgelaufen?)',
          invitationId,
        );
      }
    } else {
      this.logger.warn('no pendingContactId for invitation=%s', invitationId);
    }

    this.logger.debug(
      '[Handler] create: email=%s, phoneNumbers=%o',
      email ?? '',
      phoneNumbers ?? [],
    );
    const input = data.payload;
    input.email = email;
    input.phoneNumbers = phoneNumbers;
    await this.userWriteService.guestSignUp(input);
  }

  private async normalizePhones(
    arr?: PhoneNumberInput[],
  ): Promise<PhoneNumberInput[]> {
    const ALLOWED = new Set(Object.values(PhoneNumberType));
    const out: PhoneNumberInput[] = [];

    for (const p of arr ?? []) {
      const kind = String(p.type ?? '')
        .toUpperCase()
        .trim();
      const rawValue = String(p.number ?? '').trim();
      const isPrimary = p.isPrimary;
      const label = p.label;

      // Skip invalid types
      if (!ALLOWED.has(kind as PhoneNumberType)) {
        this.logger.warn(
          'Skipping phone: invalid kind=%s value=%s',
          kind,
          rawValue,
        );
        continue;
      }

      // Skip empty numbers
      if (!rawValue) {
        this.logger.warn('Skipping phone: empty value');
        continue;
      }

      // Convert: value -> number
      out.push({
        type: kind as PhoneNumberType,
        countryCode: 'DE',
        number: rawValue, // <-- the correct field for PhoneNumberInput
        isPrimary,
        label,
      });
    }

    return out;
  }
}
