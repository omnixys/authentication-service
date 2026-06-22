import { env } from '../../env.js';
import type { GraphQLResponse } from '../../utils/graphql-client.js';
import { gqlRequest } from '../../utils/graphql-client.js';
import type { PayloadMap } from '../../utils/graphql-types.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - ResetMutationResolver', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should accept password reset requests without leaking account existence', async () => {
    const mutation = `
      mutation {
        requestPasswordReset(email: "${env.OMNIXYS_USER_USERNAME}")
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'requestPasswordReset'>> =
      await gqlRequest(app, 'requestPasswordReset', mutation);

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.requestPasswordReset).toBe(true);
  });

  it('should reject an invalid reset token during token verification', async () => {
    const mutation = `
      mutation {
        verifyPasswordResetToken(token: "invalid-reset-token") {
          mfaRequired
          mfaMethod
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'verifyPasswordResetToken'>> =
      await gqlRequest(app, 'verifyPasswordResetToken', mutation);

    expect(result.data?.verifyPasswordResetToken).toBeUndefined();
    expect(result.errors?.length).toBeGreaterThan(0);
  });

  it('should reject invalid step-up verification input', async () => {
    const mutation = `
      mutation {
        verifyPasswordResetStepUp(input: { token: "invalid-reset-token" })
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'verifyPasswordResetStepUp'>> =
      await gqlRequest(app, 'verifyPasswordResetStepUp', mutation);

    expect(result.data?.verifyPasswordResetStepUp).toBeUndefined();
    expect(result.errors?.length).toBeGreaterThan(0);
  });

  it('should validate minimum password requirements before completing reset', async () => {
    const mutation = `
      mutation {
        completePasswordReset(input: {
          token: "invalid-reset-token"
          newPassword: "short"
        })
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'completePasswordReset'>> =
      await gqlRequest(app, 'completePasswordReset', mutation);

    expect(result.data?.completePasswordReset).toBeUndefined();
    expect(result.errors?.length).toBeGreaterThan(0);
  });
});
