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

import { LoggerPlus } from './logger-plus.js';
import { Injectable } from '@nestjs/common';
import { KafkaProducerService } from '@omnixys/kafka';

/**
 * Globaler Schlüsselname für die Producer-Singleton-Instanz.
 * Wird streng typisiert als Symbol verwaltet, um „any“ zu vermeiden.
 */
const KAFKA_PRODUCER_KEY: unique symbol = Symbol.for('__omnixysKafkaProducer__');

/**
 * Typisierte Zugriffshilfe auf den globalen Kafka-Producer.
 */
export function getGlobalKafkaProducer(): KafkaProducerService | undefined {
  return (globalThis as Record<symbol, unknown>)[KAFKA_PRODUCER_KEY] as
    | KafkaProducerService
    | undefined;
}

/**
 * Registriert eine KafkaProducerService-Instanz global.
 */
export function setGlobalKafkaProducer(producer: KafkaProducerService): void {
  (globalThis as Record<symbol, KafkaProducerService>)[KAFKA_PRODUCER_KEY] = producer;
}

/**
 * LoggerPlusService
 * – Stellt typisierte LoggerPlus-Instanzen bereit.
 * – Registriert keinen Kafka-Producer direkt (keine Zirkularabhängigkeit).
 */
@Injectable()
export class LoggerPlusService {
  /**
   * Liefert eine neue LoggerPlus-Instanz für den angegebenen Kontext.
   * @param context Klassen- oder Service-Bezeichner
   */
  getLogger(context: string): LoggerPlus {
    return new LoggerPlus(context);
  }
}
