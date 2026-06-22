import { rawGqlRequest } from '../../utils/graphql-client.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - AuthMutationResolver passwordless paths', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should accept magic-link requests without leaking account existence', async () => {
    const mutation = `
      mutation {
        sendMagicLink(email: "missing-user-${Date.now()}@omnixys.invalid")
      }
    `;

    const result = await rawGqlRequest(app, mutation, undefined, undefined, []);

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.sendMagicLink).toBe(true);
  });

  it('should generate discoverable WebAuthn authentication options', async () => {
    const mutation = `
      mutation {
        generateWebAuthnAuthOptions
      }
    `;

    const result = await rawGqlRequest(app, mutation, undefined, undefined, []);

    expect(result.errors ?? []).toHaveLength(0);
    expect(result.data?.generateWebAuthnAuthOptions).toBeDefined();
  });

  it('should reject invalid passwordless and WebAuthn authentication responses', async () => {
    const mutation = `
      mutation {
        verifyPasswordlessAuthentication(response: {}) {
          accessToken
        }
        verifyWebAuthnAuthentication(response: {}) {
          accessToken
        }
      }
    `;

    const result = await rawGqlRequest(app, mutation, undefined, undefined, []);

    expect(result.errors?.length).toBeGreaterThan(0);
    expect(result.data).toBeNull();
    expect(
      result.errors?.every(
        (error) => typeof error.extensions?.requestId === 'string',
      ),
    ).toBe(true);
  });

  it('should reject invalid TOTP and magic-link login attempts', async () => {
    const mutation = `
      mutation {
        loginTotp(input: { username: "missing-user", code: "000000" }) {
          accessToken
        }
        verifyMagicLink(token: "invalid-magic-link-token") {
          accessToken
        }
      }
    `;

    const result = await rawGqlRequest(app, mutation, undefined, undefined, []);

    expect(result.errors?.length).toBeGreaterThan(0);
    expect(result.data).toBeNull();
    expect(
      result.errors?.every(
        (error) => typeof error.extensions?.requestId === 'string',
      ),
    ).toBe(true);
  });
});
