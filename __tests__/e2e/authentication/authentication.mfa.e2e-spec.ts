import type { GraphQLResponse } from '../../utils/graphql-client.js';
import { gqlRequest, rawGqlRequest } from '../../utils/graphql-client.js';
import type { PayloadMap } from '../../utils/graphql-types.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - MfaMutationResolver', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should expose public security questions', async () => {
    const query = `
      query {
        getSecurityQuestions {
          id
          key
          question
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'getSecurityQuestions'>> =
      await gqlRequest(app, 'getSecurityQuestions', query);

    expect(result.errors ?? []).toHaveLength(0);
    expect(Array.isArray(result.data?.getSecurityQuestions)).toBe(true);
  });

  it('should protect MFA device, TOTP, WebAuthn and backup-code operations', async () => {
    const mutation = `
      mutation {
        setMfaPreference(method: NONE)
        revokeWebAuthnCredential(credentialId: "missing-credential")
        enableTotp { secret otpauth uri }
        confirmTotp(code: "000000")
        generateWebAuthnRegistrationOptions
        verifyWebAuthnRegistration(response: {})
        generateWebAuthnAuthOptions2
        verifyWebAuthnAuthentication2(response: {})
        regenerateBackupCodes
        renameWebAuthnCredential(
          credentialId: "missing-credential"
          nickname: "E2E Device"
        )
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

  it('should protect MFA device listing', async () => {
    const query = `
      query {
        listWebAuthnDevices {
          credentialId
          nickname
          deviceType
          backedUp
          createdAt
          lastUsedAt
          revokedAt
        }
      }
    `;

    const result: GraphQLResponse<Pick<PayloadMap, 'listWebAuthnDevices'>> =
      await gqlRequest(app, 'listWebAuthnDevices', query, undefined, {}, []);

    expect(result.data?.listWebAuthnDevices).toBeUndefined();
    expect(result.errors?.length).toBeGreaterThan(0);
  });
});
