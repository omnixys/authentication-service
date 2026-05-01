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

import type { INestApplication } from '@nestjs/common';
import type { Server } from 'http';
import request, { type Response } from 'supertest';

import type {
  GraphQLOperationKey,
  PayloadMap,
  VariableMap,
} from './graphql-types.js';

/// <summary>
/// Defines the generic GraphQL response structure used by tests.
/// </summary>
export interface GraphQLResponse<
  TData extends Record<
    string,
    object | string | number | boolean | null | undefined
  >,
> {
  readonly data?: TData;
  readonly errors?: ReadonlyArray<{ message: string; path?: string[] }>;
  readonly cookies?: string[];
  readonly res: Response;
}

/// <summary>
/// Global cookie storage shared between test runs.
/// </summary>
let globalCookies: string[] = [];

/// <summary>
/// Executes a typed GraphQL query or mutation.
/// The return type and variable structure are automatically inferred from PayloadMap and VariableMap.
/// </summary>
export async function gqlRequest<TKey extends GraphQLOperationKey>(
  app: INestApplication,
  operation: TKey,
  query: string,
  variables?: VariableMap[TKey],
  headers?: Readonly<Record<string, string>>,
  cookies?: readonly string[],
): Promise<GraphQLResponse<{ [K in TKey]: PayloadMap[K] }>> {
  const agent: Server = app.getHttpServer() as Server;
  let req = request(agent).post('/graphql');

  // Attach cookies
  const cookieArray: string[] =
    cookies !== undefined ? [...cookies] : [...globalCookies];
  if (cookieArray.length > 0) {
    req = req.set('Cookie', cookieArray);
  }

  // Attach headers
  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      if (value) {
        req = req.set(key, value);
      }
    }
  }

  // Payload (query + variables)
  const payload: Readonly<
    { query: string; variables: VariableMap[TKey] } | { query: string }
  > =
    variables !== undefined
      ? // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        { query, variables: variables as VariableMap[TKey] }
      : { query };

  const res: Response = await req.send(payload);

  // Normalize cookies
  const rawCookies = res.headers['set-cookie'];
  const setCookies: string[] | undefined =
    typeof rawCookies === 'string'
      ? [rawCookies]
      : Array.isArray(rawCookies)
        ? rawCookies
        : undefined;

  if (setCookies) {
    globalCookies = [...setCookies];
  }

  // Strictly typed response
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const body: Readonly<{
    data?: { [K in TKey]: PayloadMap[K] };
    errors?: Array<{ message: string; path?: string[] }>;
  }> = res.body;

  if (body.errors && body.errors.length > 0) {
    console.error(
      JSON.stringify(
        {
          level: 'ERROR',
          operation,
          message: 'GraphQL Errors',
          details: body.errors,
        },
        undefined,
        2,
      ),
    );
  }

  return {
    res,
    data: body.data,
    errors: body.errors,
    cookies: setCookies,
  };
}

export async function rawGqlRequest(
  app: INestApplication,
  query: string,
  variables?: Readonly<Record<string, unknown>>,
  headers?: Readonly<Record<string, string>>,
  cookies?: readonly string[],
): Promise<
  GraphQLResponse<Record<string, object | string | number | boolean | null>>
> {
  const agent: Server = app.getHttpServer() as Server;
  let req = request(agent).post('/graphql');

  const cookieArray: string[] =
    cookies !== undefined ? [...cookies] : [...globalCookies];
  if (cookieArray.length > 0) {
    req = req.set('Cookie', cookieArray);
  }

  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      if (value) {
        req = req.set(key, value);
      }
    }
  }

  const res: Response = await req.send(
    variables === undefined ? { query } : { query, variables },
  );

  const rawCookies = res.headers['set-cookie'];
  const setCookies: string[] | undefined =
    typeof rawCookies === 'string'
      ? [rawCookies]
      : Array.isArray(rawCookies)
        ? rawCookies
        : undefined;

  if (setCookies) {
    globalCookies = [...setCookies];
  }

  const body = res.body as {
    data?: Record<string, object | string | number | boolean | null>;
    errors?: Array<{ message: string; path?: string[] }>;
  };

  return {
    res,
    data: body.data,
    errors: body.errors,
    cookies: setCookies,
  };
}

/// <summary>
/// Clears global cookies between test sessions.
/// </summary>
export function resetCookies(): void {
  globalCookies = [];
}
