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

export interface TestUserPayload {
  id?: string;
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  role?: string;
}

export interface TestTokenPayload {
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

export interface TestSuccessPayload {
  ok: boolean;
  message?: string;
}

export interface TestSignUpPayload {
  user?: TestUserPayload;
  password?: string;
  username?: string;
  userId?: string;
  message?: string;
  token?: TestTokenPayload;
}

export interface TestGuestSignUpPayload {
  results?: Array<{
    userId: string;
    username: string;
    password: string;
    email: string;
  }>;
  message?: string;
}

// shared between PayloadMap and VariableMap
export type GraphQLOperationKey =
  | 'credentialsLogin'
  | 'refresh'
  | 'logout'
  | 'adminSignUp'
  | 'guestSignIn'
  | 'updateUser'
  | 'adminUpdateUser'
  | 'changeUserPassword'
  | 'deleteKcUser'
  | 'assignRealmRole'
  | 'removeRealmRole'
  | 'adminChangePassword'
  | 'changeMyPassword'
  | 'updateMyProfile'
  | 'requestPasswordReset'
  | 'verifyPasswordResetToken'
  | 'verifyPasswordResetStepUp'
  | 'completePasswordReset'
  | 'verifySignUp'
  | 'verifyGuestSignUp'
  | 'setMfaPreference'
  | 'listWebAuthnDevices'
  | 'revokeWebAuthnCredential'
  | 'enableTotp'
  | 'confirmTotp'
  | 'generateWebAuthnRegistrationOptions'
  | 'verifyWebAuthnRegistration'
  | 'generateWebAuthnAuthOptions2'
  | 'verifyWebAuthnAuthentication2'
  | 'regenerateBackupCodes'
  | 'renameWebAuthnCredential'
  | 'getSecurityQuestions'
  | 'generatePasswordlessOptions'
  | 'generateWebAuthnAuthOptions'
  | 'verifyPasswordlessAuthentication'
  | 'verifyWebAuthnAuthentication'
  | 'loginTotp'
  | 'sendMagicLink'
  | 'verifyMagicLink'
  | 'getById'
  | 'getByUsername'
  | 'kc_users'
  | 'meAuth'
  | 'meByToken';

/**
 * ---------------------------------------
 * GraphQL → Return type mapping
 * ---------------------------------------
 */
export interface PayloadMap extends Record<GraphQLOperationKey, unknown> {
  credentialsLogin: TestTokenPayload;
  refresh: TestTokenPayload;
  logout: TestSuccessPayload;
  adminSignUp: TestTokenPayload;
  guestSignIn: TestSignUpPayload;

  updateUser: boolean;
  adminUpdateUser: boolean;
  changeUserPassword: boolean;
  deleteKcUser: boolean;
  assignRealmRole: boolean;
  removeRealmRole: boolean;
  adminChangePassword: boolean;

  changeMyPassword: TestSuccessPayload;
  updateMyProfile: TestSuccessPayload;
  requestPasswordReset: boolean;
  verifyPasswordResetToken: { mfaRequired: boolean; mfaMethod: string };
  verifyPasswordResetStepUp: boolean;
  completePasswordReset: boolean;
  verifySignUp: TestSignUpPayload;
  verifyGuestSignUp: TestGuestSignUpPayload;

  setMfaPreference: boolean;
  listWebAuthnDevices: Array<{
    credentialId: string;
    nickname?: string;
    deviceType: string;
    backedUp: boolean;
    createdAt: string;
    lastUsedAt?: string;
    revokedAt?: string;
  }>;
  revokeWebAuthnCredential: boolean;
  enableTotp: { secret?: string; otpauth?: string; uri?: string };
  confirmTotp: boolean;
  generateWebAuthnRegistrationOptions: Record<string, unknown>;
  verifyWebAuthnRegistration: boolean;
  generateWebAuthnAuthOptions2: Record<string, unknown>;
  verifyWebAuthnAuthentication2: boolean;
  regenerateBackupCodes: string[];
  renameWebAuthnCredential: boolean;
  getSecurityQuestions: Array<{ id: string; question: string }>;

  generatePasswordlessOptions: Record<string, unknown>;
  generateWebAuthnAuthOptions: Record<string, unknown>;
  verifyPasswordlessAuthentication: TestTokenPayload;
  verifyWebAuthnAuthentication: TestTokenPayload;
  loginTotp: TestTokenPayload;
  sendMagicLink: boolean;
  verifyMagicLink: TestTokenPayload;

  getById: TestUserPayload;
  getByUsername: TestUserPayload;
  kc_users: TestUserPayload[];
  meAuth: TestUserPayload;
  meByToken: TestUserPayload;
}

/* ----------------------------------------------
 * VariableMap → Connects operation name to variable type
 * (used by gqlRequest<T> generic inference)
 * ---------------------------------------------- */

export interface VariableMap extends Record<GraphQLOperationKey, unknown> {
  credentialsLogin: LoginVariables;
  refresh: RefreshVariables;
  logout: LogoutVariables;
  adminSignUp: AdminSignUpVariables;
  guestSignIn: GuestSignInVariables;

  updateUser: UpdateUserVariables;
  adminUpdateUser: UpdateUserVariables;
  changeUserPassword: ChangePasswordVariables;
  deleteKcUser: DeleteUserVariables;
  assignRealmRole: AssignRealmRoleVariables;
  removeRealmRole: RemoveRealmRoleVariables;
  adminChangePassword: AdminChangePasswordVariables;

  changeMyPassword: ChangeMyPasswordVariables;
  updateMyProfile: UpdateMyProfileVariables;
  requestPasswordReset: RequestPasswordResetVariables;
  verifyPasswordResetToken: VerifyPasswordResetTokenVariables;
  verifyPasswordResetStepUp: VerifyPasswordResetStepUpVariables;
  completePasswordReset: CompletePasswordResetVariables;
  verifySignUp: TokenVariables;
  verifyGuestSignUp: TokenVariables;

  setMfaPreference: SetMfaPreferenceVariables;
  listWebAuthnDevices: never;
  revokeWebAuthnCredential: CredentialIdVariables;
  enableTotp: never;
  confirmTotp: CodeVariables;
  generateWebAuthnRegistrationOptions: never;
  verifyWebAuthnRegistration: ResponseVariables;
  generateWebAuthnAuthOptions2: never;
  verifyWebAuthnAuthentication2: ResponseVariables;
  regenerateBackupCodes: never;
  renameWebAuthnCredential: RenameWebAuthnCredentialVariables;
  getSecurityQuestions: never;

  generatePasswordlessOptions: EmailVariables;
  generateWebAuthnAuthOptions: never;
  verifyPasswordlessAuthentication: ResponseVariables;
  verifyWebAuthnAuthentication: ResponseVariables;
  loginTotp: LoginTotpVariables;
  sendMagicLink: EmailVariables;
  verifyMagicLink: TokenVariables;

  getById: GetByIdVariables;
  getByUsername: GetByUsernameVariables;
  kc_users: never; // no vars
  meAuth: never; // no vars
  meByToken: never; // no vars
}

/* ----------------------------------------------
 * GraphQL Operation Variable Types
 * Used with gqlRequest<T> in E2E tests.
 * ---------------------------------------------- */

/**
 * Authentication → Login
 */
export interface LoginVariables {
  input: {
    username: string;
    password: string;
  };
}

/**
 * Authentication → Refresh Token
 */
export interface RefreshVariables {
  input: {
    refreshToken: string;
  };
}

/**
 * Authentication → Logout
 */
export interface LogoutVariables {
  input?: {
    refreshToken?: string;
  };
}

/**
 * Authentication → Admin Sign-Up
 */
export interface AdminSignUpVariables {
  input: {
    email: string;
    username: string;
    password: string;
    realmRoles?: string[];
  };
}

/**
 * Authentication → Guest Sign-In
 */
export interface GuestSignInVariables {
  input: {
    email: string;
    eventCode: string;
  };
}

/**
 * User → Update
 */
export interface UpdateUserVariables {
  id: string;
  input: {
    username?: string;
    email?: string;
    firstName?: string;
    lastName?: string;
    enabled?: boolean;
  };
}

/**
 * User → Change Password
 */
export interface ChangePasswordVariables {
  id: string;
  input: {
    oldPassword: string;
    newPassword: string;
  };
}

export interface AdminChangePasswordVariables {
  input: {
    id: string;
    newPassword: string;
  };
}

/**
 * User → Assign Realm Role
 */
export interface AssignRealmRoleVariables {
  id: string;
  roleName: string;
}

/**
 * User → Remove Realm Role
 */
export interface RemoveRealmRoleVariables {
  id: string;
  roleName: string;
}

/**
 * User → Delete User
 */
export interface DeleteUserVariables {
  id: string;
}

/**
 * Me → Change My Password
 */
export interface ChangeMyPasswordVariables {
  input: {
    oldPassword: string;
    newPassword: string;
  };
}

/**
 * Me → Update My Profile
 */
export interface UpdateMyProfileVariables {
  input: {
    firstName?: string;
    lastName?: string;
    email?: string;
    phoneNumber?: string;
  };
}

/**
 * Me → Send Password Reset
 */
export interface EmailVariables {
  email: string;
}

export type RequestPasswordResetVariables = EmailVariables;

export interface VerifyPasswordResetTokenVariables {
  token: string;
}

export interface VerifyPasswordResetStepUpVariables {
  input: {
    token: string;
    code?: string;
    credentialResponse?: unknown;
    answers?: Array<{ questionId: string; answer: string }>;
  };
}

export interface CompletePasswordResetVariables {
  input: {
    token: string;
    newPassword: string;
  };
}

export interface TokenVariables {
  token: string;
}

export interface SetMfaPreferenceVariables {
  method: string;
}

export interface CredentialIdVariables {
  credentialId: string;
}

export interface CodeVariables {
  code: string;
}

export interface ResponseVariables {
  response: unknown;
}

export interface RenameWebAuthnCredentialVariables {
  credentialId: string;
  nickname: string;
}

export interface LoginTotpVariables {
  input: {
    username: string;
    code: string;
  };
}

/**
 * User → Query by ID
 */
export interface GetByIdVariables {
  id: string;
}

/**
 * User → Query by Username
 */
export interface GetByUsernameVariables {
  username: string;
}
