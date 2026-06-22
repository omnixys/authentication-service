import { env } from '../../env.js';
import type { GraphQLResponse } from '../../utils/graphql-client.js';
import { gqlRequest } from '../../utils/graphql-client.js';
import type { PayloadMap } from '../../utils/graphql-types.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - AuthQueryResolver', () => {
  let app: INestApplication;
  let authHeaders: Record<string, string> = {};

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;

    const loginMutation = `
      mutation {
        credentialsLogin(input: {
          username: "${env.OMNIXYS_ADMIN_USERNAME}"
          password: "${env.OMNIXYS_ADMIN_PASSWORD}"
        }) {
          accessToken
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'credentialsLogin'>> =
      await gqlRequest(app, 'credentialsLogin', loginMutation);

    const accessToken = result.data?.credentialsLogin?.accessToken;
    expect(accessToken).toBeDefined();
    authHeaders = { Authorization: `Bearer ${accessToken}` };
  });

  afterAll(shutdownTestApp);

  it('should query all Keycloak users', async () => {
    const query = `
      query {
        kc_users {
          id
          username
          email
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'kc_users'>> =
      await gqlRequest(app, 'kc_users', query, undefined, authHeaders);

    expect(result.errors ?? []).toHaveLength(0);
    expect(Array.isArray(result.data?.kc_users)).toBe(true);
  });

  it('should resolve the current user from the Authorization header', async () => {
    const query = `
      query {
        meByToken {
          id
          username
          email
          role
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'meByToken'>> =
      await gqlRequest(app, 'meByToken', query, undefined, authHeaders, []);

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.meByToken?.id).toBeDefined();
  });
});
