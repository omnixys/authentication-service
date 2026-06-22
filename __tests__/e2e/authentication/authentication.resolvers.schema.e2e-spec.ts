import { rawGqlRequest } from '../../utils/graphql-client.js';
import { createTestApp, shutdownTestApp } from '../setup-e2e.js';
import type { INestApplication } from '@nestjs/common';

describe('Authentication E2E - Resolver schema coverage', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const setup = await createTestApp();
    app = setup.app;
  });

  afterAll(shutdownTestApp);

  it('should expose every authentication resolver operation through GraphQL', async () => {
    const query = `
      query ResolverSchema {
        __schema {
          queryType {
            fields { name }
          }
          mutationType {
            fields { name }
          }
        }
      }
    `;

    const result = await rawGqlRequest(app, query);

    expect(result.errors).toBeUndefined();

    const schema = result.data?.__schema as
      | {
          queryType?: { fields?: Array<{ name: string }> };
          mutationType?: { fields?: Array<{ name: string }> };
        }
      | undefined;

    const queryFields = new Set(
      schema?.queryType?.fields?.map((field) => field.name) ?? [],
    );
    const mutationFields = new Set(
      schema?.mutationType?.fields?.map((field) => field.name) ?? [],
    );

    expect([...queryFields]).toEqual(
      expect.arrayContaining([
        'kc_users',
        'meByToken',
        'meAuth',
        'getById',
        'getByUsername',
        'listWebAuthnDevices',
        'getSecurityQuestions',
      ]),
    );

    expect([...mutationFields]).toEqual(
      expect.arrayContaining([
        'credentialsLogin',
        'refresh',
        'logout',
        'generatePasswordlessOptions',
        'generateWebAuthnAuthOptions',
        'verifyPasswordlessAuthentication',
        'verifyWebAuthnAuthentication',
        'loginTotp',
        'sendMagicLink',
        'verifyMagicLink',
        'adminUpdateUser',
        'adminChangePassword',
        'deleteKcUser',
        'assignRealmRole',
        'removeRealmRole',
        'adminSignUp',
        'changeMyPassword',
        'updateMyProfile',
        'verifyGuestSignUp',
        'verifySignUp',
        'requestPasswordReset',
        'verifyPasswordResetToken',
        'verifyPasswordResetStepUp',
        'completePasswordReset',
        'setMfaPreference',
        'revokeWebAuthnCredential',
        'enableTotp',
        'confirmTotp',
        'generateWebAuthnRegistrationOptions',
        'verifyWebAuthnRegistration',
        'generateWebAuthnAuthOptions2',
        'verifyWebAuthnAuthentication2',
        'regenerateBackupCodes',
        'renameWebAuthnCredential',
      ]),
    );
  });
});
