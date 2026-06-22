/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
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

import { env } from '../../env.js';
import { gqlRequest } from '../../utils/graphql-client.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

/**
 * 💡 Dieser Test deckt den gesamten Admin Flow ab:
 * - Login mit Admin-Credentials
 * - AdminSignUp (legt neuen Benutzer an)
 * - UpdateUser (Profilfelder)
 * - assignRealmRole / removeRealmRole
 * - deleteKcUser
 */
describe('🛡️ Authentication E2E - Admin Operations (Full Flow)', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let accessToken: string | undefined = undefined;
  let authHeaders: Record<string, string> = {};
  let createdUserId: string | undefined = undefined;
  let createdUsername: string | undefined = undefined;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;

    // 🔹 Login als Admin
    const adminLoginQuery = `
      mutation {
        credentialsLogin(input: {
          username: "${env.OMNIXYS_ADMIN_USERNAME ?? 'admin'}",
          password: "${env.OMNIXYS_ADMIN_PASSWORD ?? 'p'}"
        }) { accessToken }
      }
    `;
    const { data, cookies: setCookies } = await gqlRequest(
      app,
      'credentialsLogin',
      adminLoginQuery,
    );
    cookies = setCookies ?? [];
    accessToken = data?.credentialsLogin?.accessToken;
    authHeaders = { Authorization: `Bearer ${accessToken}` };

    expect(accessToken).toBeDefined();
  });

  afterAll(shutdownTestApp);

  // -----------------------------------------------------
  // 🔹 ADMIN SIGN-UP (neuer Benutzer)
  // -----------------------------------------------------
  it('should create a new user via adminSignUp', async () => {
    const unique = Date.now();
    createdUsername = `admin-op-${unique}`;
    const email = `admin-op-${unique}@omnixys.com`;

    const query = `
      mutation {
        adminSignUp(
          input: {
            username: "${createdUsername}"
            email: "${email}"
            password: "TempPass123!"
            firstName: "E2E"
            lastName: "AdminFlow"
            phoneNumbers: []
          }
        ) {
          accessToken
        }
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      'adminSignUp',
      query,
      undefined,
      authHeaders,
      cookies,
    );
    expect(errors).toBeUndefined();
    expect(data?.adminSignUp?.accessToken).toBeDefined();
  });

  // -----------------------------------------------------
  // 🔹 GET USER ID (getByUsername)
  // -----------------------------------------------------
  it('should fetch the created user by username', async () => {
    const query = `
      query {
        getByUsername(username: "${createdUsername}") {
          id
          username
          email
        }
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      'getByUsername',
      query,
      undefined,
      authHeaders,
      cookies,
    );
    expect(errors).toBeUndefined();
    createdUserId = data?.getByUsername?.id ?? undefined;
    expect(createdUserId).toMatch(/^[\w-]+$/);
  });

  // -----------------------------------------------------
  // 🔹 UPDATE USER PROFILE
  // -----------------------------------------------------
  it('should update the user profile (adminUpdateUser)', async () => {
    const query = `
      mutation {
        adminUpdateUser(
          id: "${createdUserId}",
          input: {
            firstName: "Updated"
            lastName: "AdminUser"
            email: "updated-${createdUsername}@omnixys.com"
          }
        )
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      'adminUpdateUser',
      query,
      undefined,
      authHeaders,
      cookies,
    );
    expect(errors).toBeUndefined();
    expect(data?.adminUpdateUser).toBe(true);
  });

  it('should change the user password (adminChangePassword)', async () => {
    const query = `
      mutation {
        adminChangePassword(
          input: {
            id: "${createdUserId}"
            newPassword: "AdminChanged123!"
          }
        )
      }
    `;
    const { data, errors } = await gqlRequest(
      app,
      'adminChangePassword',
      query,
      undefined,
      authHeaders,
      cookies,
    );
    expect(errors).toBeUndefined();
    expect(data?.adminChangePassword).toBe(true);
  });

  // -----------------------------------------------------
  // 🔹 ASSIGN + REMOVE ROLE
  // -----------------------------------------------------
  it('should assign and remove ADMIN role', async () => {
    const assign = `mutation { assignRealmRole(id: "${createdUserId}", roleName: ADMIN) }`;
    const remove = `mutation { removeRealmRole(id: "${createdUserId}", roleName: ADMIN) }`;

    const a = await gqlRequest(
      app,
      'assignRealmRole',
      assign,
      undefined,
      authHeaders,
      cookies,
    );
    const r = await gqlRequest(
      app,
      'removeRealmRole',
      remove,
      undefined,
      authHeaders,
      cookies,
    );

    expect(a.errors ?? []).toHaveLength(0);
    expect(r.errors ?? []).toHaveLength(0);
    expect(a.data?.assignRealmRole).toBe(true);
    expect(r.data?.removeRealmRole).toBe(true);
  });

  // -----------------------------------------------------
  // 🔹 DELETE USER
  // -----------------------------------------------------
  it('should delete the created user', async () => {
    const query = `mutation { deleteKcUser(id: "${createdUserId}") }`;
    const { data, errors } = await gqlRequest(
      app,
      'deleteKcUser',
      query,
      undefined,
      authHeaders,
      cookies,
    );
    expect(errors).toBeUndefined();
    expect(data?.deleteKcUser).toBe(true);
  });
});
