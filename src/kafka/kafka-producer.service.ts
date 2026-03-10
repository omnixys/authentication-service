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
 * For more information, visit <https://www.gnu.org/licenses/>.
 */
import { CreateTicketDTO } from '../authentication/models/dtos/create-ticket.dto.js';
import { UserIdDTO } from '../authentication/models/dtos/kc-sign-up.dto.js';
import { UserDTO, UserUpdateDTO } from '../authentication/models/dtos/user.dto.js';
import { KafkaCircuitBreaker } from '../config/kafka-circuit-breaker.js';
import { setGlobalKafkaProducer } from '../logger/logger-plus.service.js';
import type { TraceContext } from '../trace/trace-context.util.js';
import type { KafkaEnvelope } from './decorators/kafka-envelope.type.js';
import { KafkaHeaderBuilder } from './kafka-header-builder.js';
import { KafkaTopics } from './kafka-topic.properties.js';
import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { Producer, ProducerRecord } from 'kafkajs';

/**
 * Verwaltet den Kafka Producer als langlebige, wiederverwendbare Instanz.
 * Fire-and-Forget-sicher, Trace- und Logging-fähig.
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private isReady = false;
  private isShuttingDown = false;
  private readonly circuit = new KafkaCircuitBreaker(5, 10000);

  constructor(@Inject('KAFKA_PRODUCER') private readonly producer: Producer) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.producer.connect();
      setGlobalKafkaProducer(this);
      this.isReady = true;

      console.debug('Kafka producer connected');
    } catch (err) {
      console.debug('Kafka producer connection failed %o', err);
      throw err;
    }
  }

  /**
   * Sendet eine Nachricht an das angegebene Topic.
   * Fehler führen nicht zum Abbruch (Fire-and-Forget).
   */
  async send<T>(topic: string, message: KafkaEnvelope<T>, trace?: TraceContext): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    if (!this.isReady) {
      return;
    }

    if (!this.circuit.canExecute()) {
      console.warn('Kafka circuit OPEN – dropping message for topic %s', topic);
      return;
    }

    const headers = KafkaHeaderBuilder.buildStandardHeaders(
      topic,
      message.event,
      trace,
      message.version,
      message.service,
    );
    const record: ProducerRecord = {
      topic,
      messages: [{ value: JSON.stringify(message), headers }],
    };

    try {
      await this.producer.send({
        ...record,
        acks: -1,
        timeout: 5000,
      });

      this.circuit.recordSuccess();
    } catch (err) {
      console.error('Kafka send failed for topic %s → %o', topic, err);

      const previousState = this.circuit.getState();
      this.circuit.recordFailure();
      const newState = this.circuit.getState();

      if (previousState !== newState) {
        console.warn('Kafka circuit state changed: %s → %s', previousState, newState);
      }
    }
  }

  async createProviderUser(
    payload: { userId: string; email?: string; username?: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'createProviderUser',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.user.createProviderUser, envelope, trace);
  }

  async sendRequestReset(
    payload: { rawToken: string; email: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'addUserId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.notification.sendRequestReset, envelope, trace);
  }

  async sendMagicLink(
    payload: { token: string; email: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'sendMagicLink',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.notification.sendMagigLink, envelope, trace);
  }

  async addUserId(payload: UserIdDTO, service: string, trace?: TraceContext): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'addUserId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.user.addId, envelope, trace);
  }

  async createUserAddresses(
    payload: { userId: string; token?: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'createUserAddresses',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.address.createUserAddresses, envelope, trace);
  }

  async createUser(payload: UserDTO, service: string, trace?: TraceContext): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'createUser',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.user.createUser, envelope, trace);
  }

  async notifyUser(
    payload: {
      userId: string;
      password: string;
      username: string;
      invitationId: string;
      firstName: string;
      lastName: string;
    },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'notifyUser',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.notification.sendCredentials, envelope, trace);
  }

  //   async sendPasswordResetNotification(
  //     payload: {
  //       userEmail: string;
  //       username: string;
  //       firstName: string;
  //       lastName: string;
  //       securityQuestion: string;
  //       securityAnswer: string;
  //     },
  //     service: string,
  //     trace?: TraceContext,
  //   ): Promise<void> {
  //     const envelope: KafkaEnvelope<typeof payload> = {
  //       event: 'resetPassword',
  //       service,
  //       version: 'v1',
  //       trace,
  //       payload,
  //     };
  // await this.send(KafkaTopics.notification.resetPassword, envelope, trace);
  //   }

  async addEventRole(
    payload: {
      userId: string;
      eventId: string;
      actorId: string;
    },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'addEventId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.event.addUserRole, envelope, trace);
  }

  async deleteUser(payload: { id: string }, service: string, trace?: TraceContext): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'deleteUser',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.user.deleteUser, envelope, trace);
  }

  async deleteAddresses(
    payload: { id: string },
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'deleteAddresses',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.address.deleteAddresses, envelope, trace);
  }

  async updateUser(payload: UserUpdateDTO, service: string, trace?: TraceContext): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'sendUserId',
      service,
      version: 'v1',
      trace,
      payload,
    };
    await this.send(KafkaTopics.user.updateUser, envelope, trace);
  }

  async createTicket(
    payload: CreateTicketDTO,
    service: string,
    trace?: TraceContext,
  ): Promise<void> {
    const envelope: KafkaEnvelope<typeof payload> = {
      event: 'createTicket',
      service,
      version: 'v1',
      trace,
      payload,
    };
    console.debug('kafkaTopic: %s', KafkaTopics.ticket.createTicket);
    await this.send(KafkaTopics.ticket.createTicket, envelope, trace);
  }

  async disconnect(): Promise<void> {
    if (this.producer) {
      await this.producer.disconnect();
      console.debug('[KafkaProducerService] 🧹 Disconnected cleanly');
    }
  }

  async onModuleDestroy(): Promise<void> {
    this.isShuttingDown = true;
    await this.disconnect();
  }

  async onApplicationShutdown(): Promise<void> {
    await this.disconnect();
  }
}
