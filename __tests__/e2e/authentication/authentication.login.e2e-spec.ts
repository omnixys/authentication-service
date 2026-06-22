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
import { gqlRequest } from '../../utils/graphql-client.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('🔐 Authentication E2E - Login/Refresh/Logout', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let accessToken: string | undefined = undefined;
  let refreshToken: string | undefined = undefined;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should login successfully', async () => {
    const username = env.OMNIXYS_ADMIN_USERNAME;
    const password = env.OMNIXYS_ADMIN_PASSWORD;

    const query = `
      mutation {
        credentialsLogin(input: { username: "${username}", password: "${password}" }) {
          accessToken
          refreshToken
        }
      }
    `;
    const {
      data,
      errors,
      cookies: setCookies,
    } = await gqlRequest(app, 'credentialsLogin', query);
    expect(errors).toBeUndefined();

    cookies = setCookies ?? [];
    accessToken = data?.credentialsLogin?.accessToken ?? undefined;
    refreshToken = data?.credentialsLogin?.refreshToken ?? undefined;

    expect(accessToken).toBeDefined();
    expect(refreshToken).toMatch(/^[-\w.]+$/);
  });

  it('should refresh tokens', async () => {
    const query = `
      mutation { refresh { accessToken refreshToken } }
    `;
    const { data, errors } = await gqlRequest(app, 'refresh', query);
    expect(errors).toBeUndefined();
    expect(data?.refresh?.accessToken).toBeDefined();
  });

  it('should logout successfully', async () => {
    const query = `
      mutation { logout { ok message } }
    `;
    const { data, errors } = await gqlRequest(
      app,
      'logout',
      query,
      undefined,
      undefined,
      cookies,
    );
    expect(errors).toBeUndefined();
    expect(data?.logout?.ok).toBe(true);
  });
});
