import type { GraphQLResponse } from '../../utils/graphql-client.js';
import { gqlRequest } from '../../utils/graphql-client.js';
import type { PayloadMap } from '../../utils/graphql-types.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - RegisterResolver', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should reject an invalid sign-up verification token', async () => {
    const mutation = `
      mutation {
        verifySignUp(token: "invalid-sign-up-token") {
          message
          userId
          username
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'verifySignUp'>> =
      await gqlRequest(app, 'verifySignUp', mutation);

    expect(result.data?.verifySignUp).toBeUndefined();
    expect(result.errors?.length).toBeGreaterThan(0);
  });
});
