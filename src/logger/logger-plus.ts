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

import { env } from '../config/env.js';
import { getLogger } from './get-logger.js';
import { getGlobalKafkaProducer } from './logger-plus.service.js';
import { KafkaTopics } from '@omnixys/kafka';
import type { LogEventDTO, TraceContext } from '@omnixys/shared';
import { LogLevel } from '@omnixys/shared';
import {
  context,
  SpanKind,
  SpanStatusCode,
  trace,
  type SpanContext,
  type Tracer,
} from '@opentelemetry/api';
import { format } from 'util';

function normalizeForLogging(arg: unknown): unknown {
  if (arg && typeof arg === 'object') {
    // Wandelt class-transformer-Objekte in Plain Objects um
    return Array.isArray(arg)
      ? arg.map(normalizeForLogging)
      : JSON.parse(JSON.stringify(arg));
  }
  return arg;
}

/**
 * LoggerPlus
 * - schreibt nach Pino
 * - erstellt OTEL-Spans
 * - sendet parallel Fire-and-Forget-Kafka-Event
 */
export class LoggerPlus {
  private traceContext?: TraceContext;
  private readonly pinoLogger;
  private readonly tracer: Tracer;
  private readonly serviceName = `omnixys-${env.SERVICE}-service`;

  constructor(private readonly contextName: string) {
    this.pinoLogger = getLogger(contextName);
    this.tracer = trace.getTracer('logger-plus');
  }

  withContext(traceContext?: TraceContext): this {
    this.traceContext = traceContext;
    return this;
  }

  private sendLog(level: LogLevel, message: string): void {
    const manualCtx = this.traceContext;
    let traceCtx = manualCtx;

    if (!traceCtx) {
      const activeSpan = trace.getSpan(context.active());
      if (activeSpan) {
        const spanCtx = activeSpan.spanContext();
        traceCtx = {
          traceId: spanCtx.traceId,
          spanId: spanCtx.spanId,
          sampled: String(spanCtx.traceFlags === 1),
        };
      }
    }

    const links: Array<{ context: SpanContext }> = [];
    if (manualCtx?.traceId && manualCtx.spanId) {
      links.push({
        context: {
          traceId: manualCtx.traceId,
          spanId: manualCtx.spanId,
          traceFlags: manualCtx.sampled ? 1 : 0,
          isRemote: true,
        },
      });
    }

    void this.tracer.startActiveSpan(
      `logger.${level.toLowerCase()}`,
      { kind: SpanKind.INTERNAL, links },
      async (span) => {
        try {
          const producer = getGlobalKafkaProducer();
          if (producer) {
            const logPayload: LogEventDTO = {
              level,
              message,
              service: this.serviceName,
              context: this.contextName,
              traceContext: traceCtx,
              timestamp: new Date().toISOString(),
            };

            // Fire-and-Forget: blockiert nicht
            void producer.send<typeof KafkaTopics.logstream.authentication>(
              KafkaTopics.logstream.authentication,
              logPayload,
              this.serviceName,
              traceCtx,
            );
          }
          span.setStatus({ code: SpanStatusCode.OK });
        } catch (err) {
          span.recordException(err as Error);
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: (err as Error).message,
          });
        } finally {
          span.end();
        }
      },
    );
  }

  /** Formatierte Nachricht erzeugen – normalisiert auch [Object: null prototype] */
  private fmt(message: string, ...args: unknown[]): string {
    // Deep-normalize: entfernt [Object: null prototype] aus Nest/GraphQL-Objekten
    const normalized = args.map(normalizeForLogging);
    return format(message, ...normalized);
  }

  log(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.info(msg);
  }

  debug(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.debug(msg);
    this.sendLog(LogLevel.DEBUG, msg);
  }

  info(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.info(msg);
    this.sendLog(LogLevel.INFO, msg);
  }

  warn(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.warn(msg);
    this.sendLog(LogLevel.WARN, msg);
  }

  error(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.error(msg);
    this.sendLog(LogLevel.ERROR, msg);
  }

  trace(message: string, ...args: unknown[]): void {
    const msg = this.fmt(message, ...args);
    this.pinoLogger.trace?.(msg);
    this.sendLog(LogLevel.TRACE, msg);
  }
}
