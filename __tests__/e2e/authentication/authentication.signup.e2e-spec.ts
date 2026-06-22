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

describe('👑 Authentication E2E - User SignUp Flow (Full Lifecycle)', () => {
  let app: INestApplication;
  let cookies: string[] = [];
  let createdUserId: string | undefined = undefined;
  let createdUsername: string | undefined = undefined;
  let createdEmail: string | undefined = undefined;
  let userAccessToken: string | undefined = undefined;
  let userAuthHeaders: Record<string, string> = {};

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  // -----------------------------------------------------
  // 🔹 SIGN UP NEW USER
  // -----------------------------------------------------
  it('should sign up a new user successfully', async () => {
    const adminLogin = await gqlRequest(
      app,
      'credentialsLogin',
      `mutation {
        credentialsLogin(input: {
          username: "${env.OMNIXYS_ADMIN_USERNAME}"
          password: "${env.OMNIXYS_ADMIN_PASSWORD}"
        }) { accessToken }
      }`,
    );
    expect(adminLogin.errors).toBeUndefined();
    const adminAccessToken = adminLogin.data?.credentialsLogin?.accessToken;
    expect(adminAccessToken).toBeDefined();

    const unique = Date.now();
    createdUsername = `live-test-${unique}`;
    createdEmail = `caleb+${unique}@omnixys.com`;

    const query = `
      mutation {
        adminSignUp(
          input: {
            username: "${createdUsername}"
            email: "${createdEmail}"
            password: "OldPass123!"
            firstName: "Caleb"
            lastName: "SignupFlow"
            phoneNumbers: []
          }
        ) {
          accessToken
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'adminSignUp'>> =
      await gqlRequest(
        app,
        'adminSignUp',
        query,
        undefined,
        { Authorization: `Bearer ${adminAccessToken}` },
        adminLogin.cookies,
      );

    expect(result.errors).toBeUndefined();
    expect(result.data?.adminSignUp?.accessToken).toBeDefined();
  });

  // -----------------------------------------------------
  // 🔹 LOGIN WITH NEW USER
  // -----------------------------------------------------
  it('should login with the new user credentials', async () => {
    expect(createdUsername).toBeDefined();

    const query = `
      mutation {
        credentialsLogin(input: {
          username: "${createdUsername}",
          password: "OldPass123!"
        }) {
          accessToken
          refreshToken
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'credentialsLogin'>> =
      await gqlRequest(app, 'credentialsLogin', query);

    expect(result.errors).toBeUndefined();

    cookies = result.cookies ?? [];
    userAccessToken = result.data?.credentialsLogin?.accessToken;
    userAuthHeaders = { Authorization: `Bearer ${userAccessToken}` };

    expect(userAccessToken).toBeDefined();
  });

  // -----------------------------------------------------
  // 🔹 QUERY: GetByUsername + GetById
  // -----------------------------------------------------
  it('should fetch user by username and verify ID', async () => {
    const queryUsername = `
      query {
        getByUsername(username: "${createdUsername}") {
          id username email
        }
      }
    `;

    const resultUsername: GraphQLResponse<Pick<PayloadMap, 'getByUsername'>> =
      await gqlRequest(
        app,
        'getByUsername',
        queryUsername,
        undefined,
        userAuthHeaders,
        cookies,
      );

    expect(resultUsername.errors).toBeUndefined();

    createdUserId = resultUsername.data?.getByUsername?.id ?? undefined;
    expect(createdUserId).toMatch(/^[\w-]+$/);

    const queryId = `
      query {
        getById(id: "${createdUserId}") { id username email }
      }
    `;

    const resultId: GraphQLResponse<Pick<PayloadMap, 'getById'>> =
      await gqlRequest(
        app,
        'getById',
        queryId,
        undefined,
        userAuthHeaders,
        cookies,
      );

    expect(resultId.errors).toBeUndefined();
    expect(resultId.data?.getById?.id).toBe(createdUserId);
  });

  // -----------------------------------------------------
  // 🔹 USER MUTATION: UpdateMyProfile
  // -----------------------------------------------------
  it('should update user profile successfully', async () => {
    const query = `
      mutation {
        updateMyProfile(
          input: {
            firstName: "Caleb"
            lastName: "Updated"
            email: "${createdEmail}"
          }
        ) {
          ok
          message
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'updateMyProfile'>> =
      await gqlRequest(
        app,
        'updateMyProfile',
        query,
        undefined,
        userAuthHeaders,
        cookies,
      );

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.updateMyProfile?.ok).toBe(true);
  });

  // -----------------------------------------------------
  // 🔹 USER MUTATION: ChangeMyPassword
  // -----------------------------------------------------
  it('should change the user password successfully', async () => {
    const query = `
      mutation {
        changeMyPassword(
          input: {
            oldPassword: "OldPass123!"
            newPassword: "NewPass123!"
          }
        ) {
          ok
          message
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'changeMyPassword'>> =
      await gqlRequest(
        app,
        'changeMyPassword',
        query,
        undefined,
        userAuthHeaders,
        cookies,
      );

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.changeMyPassword?.ok).toBe(true);
  });

  // -----------------------------------------------------
  // 🔹 VERIFY LOGIN WITH NEW PASSWORD
  // -----------------------------------------------------
  it('should login again with the new password', async () => {
    const query = `
      mutation {
        credentialsLogin(input: {
          username: "${createdUsername}"
          password: "NewPass123!"
        }) {
          accessToken
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'credentialsLogin'>> =
      await gqlRequest(app, 'credentialsLogin', query);

    expect(result.errors).toBeUndefined();
    expect(result.data?.credentialsLogin?.accessToken).toBeDefined();
  });

  // -----------------------------------------------------
  // 🔹 DELETE USER (als Admin)
  // -----------------------------------------------------
  it('should delete the created user as admin', async () => {
    expect(createdUserId).toBeDefined();

    // 🔐 Login als Admin
    const adminLoginQuery = `
      mutation {
        credentialsLogin(input: {
          username: "${env.OMNIXYS_ADMIN_USERNAME}",
          password: "${env.OMNIXYS_ADMIN_PASSWORD}"
        }) { accessToken }
      }
    `;

    const adminResult: GraphQLResponse<Pick<PayloadMap, 'credentialsLogin'>> =
      await gqlRequest(app, 'credentialsLogin', adminLoginQuery);

    expect(adminResult.errors ?? []).toHaveLength(0);
    const adminAccessToken =
      adminResult.data?.credentialsLogin?.accessToken ?? undefined;
    expect(adminAccessToken).toBeDefined();

    const adminAuthHeaders = { Authorization: `Bearer ${adminAccessToken}` };

    const deleteQuery = `mutation { deleteKcUser(id: "${createdUserId}") }`;
    const deleteResult: GraphQLResponse<Pick<PayloadMap, 'deleteKcUser'>> =
      await gqlRequest(
        app,
        'deleteKcUser',
        deleteQuery,
        undefined,
        adminAuthHeaders,
      );

    expect(deleteResult.errors).toBeUndefined();
    expect(deleteResult.data?.deleteKcUser).toBe(true);

    createdUserId = undefined;
  });
});
