// /**
//  * @license GPL-3.0-or-later
//  * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
//  *
//  * This program is free software: you can redistribute it and/or modify
//  * it under the terms of the GNU General Public License as published by
//  * the Free Software Foundation, either version 3 of the License, or
//  * (at your option) any later version.
//  *
//  * This program is distributed in the hope that it will be useful,
//  * but WITHOUT ANY WARRANTY; without even the implied warranty of
//  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
//  * See the GNU General Public License for more details.
//  *
//  * For more information, visit <https://www.gnu.org/licenses/>.
//  */

// /**
//  * Common error utilities for REST/Fastify context.
//  * Provides an input validation error and OpenTelemetry span error handler.
//  * @packageDocumentation
//  */

import { BadRequestException } from '@nestjs/common';

// /**
//  * Custom error class for bad user input.
//  * Compatible with NestJS and Fastify exception filters.
//  */
export class BadUserInputException extends BadRequestException {
  constructor(message: string, cause?: Error) {
    super({
      statusCode: 400,
      message,
      cause: cause?.message,
      error: 'Bad User Input',
    });
  }
}

// /**
//  * Handles an error within an OpenTelemetry span and logs it.
//  *
//  * @param span - The active tracing span.
//  * @param error - The caught error.
//  * @param logger - The custom logger service.
//  * @param method - The method name for logging context.
//  * @throws The original error after recording it in the span.
//  */
// export function handleSpanError(
//   span: Span,
//   error: unknown,

//   method: string,
// ): never {
//   if (error instanceof Error) {
//     span.recordException(error);
//     span.setStatus({ code: 2, message: error.message });
//     void console.error(`${method} failed: ${error.message}`, error);
//   } else {
//     span.setStatus({ code: 2, message: 'Unknown error' });
//     void console.error(`${method}: Unknown error`, error);
//   }
//   throw error;
// }
