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

/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { env } from '../../env.js';
import type { GraphQLResponse } from '../../utils/graphql-client.js';
import { gqlRequest } from '../../utils/graphql-client.js';
import type { PayloadMap } from '../../utils/graphql-types.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('👤 Authentication E2E - User Operations', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let accessToken: string | undefined = undefined;
  let authHeaders: Record<string, string> = {};

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;

    const loginQuery = `
      mutation {
        credentialsLogin(input: {
          username: "${env.OMNIXYS_USER_USERNAME}",
          password: "${env.OMNIXYS_USER_PASSWORD}"
        }) { accessToken }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'credentialsLogin'>> =
      await gqlRequest(app, 'credentialsLogin', loginQuery);

    expect(result.errors).toBeUndefined();
    accessToken = result.data?.credentialsLogin?.accessToken ?? undefined;
    expect(accessToken).toBeDefined();

    cookies = result.cookies ?? [];
    authHeaders = { Authorization: `Bearer ${accessToken}` };
  });

  afterAll(shutdownTestApp);

  it('should query meAuth()', async () => {
    const query = `query { meAuth { id username email } }`;

    const result: GraphQLResponse<Pick<PayloadMap, 'meAuth'>> = await gqlRequest(
      app,
      'meAuth',
      query,
      undefined,
      authHeaders,
      cookies,
    );

    expect(result.errors).toBeUndefined();
    expect(result.data?.meAuth?.username).toBeDefined();
  });

  it('should request a password reset without leaking account existence', async () => {
    const mutation = `mutation { requestPasswordReset(email: "${env.OMNIXYS_USER_USERNAME}") }`;

    const result: GraphQLResponse<Pick<PayloadMap, 'requestPasswordReset'>> =
      await gqlRequest(
        app,
        'requestPasswordReset',
        mutation,
        undefined,
        authHeaders,
        cookies,
      );

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.requestPasswordReset).toBe(true);
  });
});
