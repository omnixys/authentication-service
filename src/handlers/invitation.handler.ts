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

import { GuestMagicLinkMetricsService } from '../authentication/metrics/guest-magic-link.metrics.service.js';
import { AdminWriteService } from '../authentication/services/admin-write.service.js';
import { AuthWriteService } from '../authentication/services/authentication-write.service.js';
import { AuthenticateReadService } from '../authentication/services/read.service.js';
import { Injectable, Optional } from '@nestjs/common';
import { ContextAccessor } from '@omnixys/context-ts';
import type {
  GuestMagicLinkRequestDTO,
  UserIdDTO,
  UserIdListDTO,
} from '@omnixys/contracts-ts';
import { RealmRoleType } from '@omnixys/contracts-ts';
import {
  IKafkaEventContext,
  KAFKA_HEADERS,
  KafkaEvent,
  KafkaEventHandler,
  KafkaTopics,
} from '@omnixys/kafka-ts';
import { OmnixysLogger } from '@omnixys/logger-ts';
import { TraceRunner } from '@omnixys/observability-ts';

/**
 * Central Kafka Authentication Handler.
 *
 * Design principles:
 * - One class per domain (authentication)
 * - One method per Kafka topic
 * - Strict typing per method
 * - No switch/case
 * - No casting
 */
@KafkaEventHandler('invitation')
@Injectable()
export class InvitationHandler {
  private readonly logger;

  /**
   * Creates a new instance of {@link EventHandler}.
   *
   * @param loggerService - The central logger service used for structured logging.
   * @param userService - The service responsible for handling system-level user operations.
   */
  constructor(
    private readonly omnixysLogger: OmnixysLogger,
    private readonly adminWriteService: AdminWriteService,
    private readonly authenticationReadService: AuthenticateReadService,
    private readonly authWriteService: AuthWriteService,
    @Optional()
    private readonly magicLinkMetrics?: GuestMagicLinkMetricsService,
  ) {
    this.logger = this.omnixysLogger.log(
      this.constructor.name,
      'service:authentication',
    );
  }

  @KafkaEvent(KafkaTopics.authentication.requestGuestMagicLink)
  async handleRequestGuestMagicLink(
    payload: GuestMagicLinkRequestDTO,
  ): Promise<void> {
    return TraceRunner.run('[HANDLER] Request Guest Magic Link', async () => {
      try {
        await this.authWriteService.requestGuestMagicLink(payload);
      } catch (error) {
        const result =
          error instanceof Error && error.name === 'TooManyRequestsException'
            ? 'RATE_LIMITED'
            : 'INTERNAL_FAILURE';
        if (result === 'RATE_LIMITED') {
          this.magicLinkMetrics?.recordRateLimit();
        }
        this.logger.warn('guest_magic_link_issue: %o', {
          result,
          correlationId: payload.correlationId,
          channel: payload.channel,
        });
      }
    });
  }

  @KafkaEvent(KafkaTopics.authentication.deleteGuest)
  async handleDeleteGuest(
    payload: UserIdDTO,
    context: IKafkaEventContext,
  ): Promise<void> {
    return TraceRunner.run('[HANDLER] Delete Guest', async () => {
      const headers = context.headers;
      const actorId =
        ContextAccessor.get()?.principal?.actorId ??
        headers[KAFKA_HEADERS.ACTOR_ID] ??
        'unknown';

      this.logger.debug(
        'handleDeleteGuestAccount: %s | actorId=%s',
        payload.userId,
        actorId,
      );

      const user = await this.authenticationReadService.findById(
        payload.userId,
      );
      if (user.role !== RealmRoleType.GUEST) {
        return;
      }
      await this.adminWriteService.deleteUser(payload.userId, actorId);
    });
  }

  @KafkaEvent(KafkaTopics.authentication.deleteGuestList)
  async handleDeleteGuestList(
    payload: UserIdListDTO,
    context: IKafkaEventContext,
  ): Promise<void> {
    return TraceRunner.run('[HANDLER] Delete Guest List', async () => {
      const headers = context.headers;
      const actorId =
        ContextAccessor.get()?.principal?.actorId ??
        headers[KAFKA_HEADERS.ACTOR_ID] ??
        'unknown';

      this.logger.debug(
        'handleDeleteGuestAccountList: %o | actorId=%s',
        payload.userIds,
        actorId,
      );

      const users = await this.authenticationReadService.findByIds(
        payload.userIds,
      );

      const guestUsers = users.filter((u) => u.role === RealmRoleType.GUEST);
      await Promise.all(
        guestUsers.map((u) => this.adminWriteService.deleteUser(u.id, actorId)),
      );
    });
  }
}
