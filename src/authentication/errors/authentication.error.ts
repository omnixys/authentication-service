import { ContextAccessor } from '@omnixys/context-ts';
import {
  FrameworkException,
  UserNotFoundException as ContractUserNotFoundException,
  type FrameworkExceptionOptions,
} from '@omnixys/contracts-ts';

function options(
  metadata: Readonly<Record<string, unknown>> = {},
  cause?: unknown,
  diagnostics: Readonly<Record<string, unknown>> = {},
): FrameworkExceptionOptions {
  const context = ContextAccessor.get();
  return {
    cause,
    context: {
      requestId: context?.requestId,
      correlationId: context?.correlationId,
      traceId: context?.trace?.traceId,
      actorId: context?.principal?.actorId,
      tenantId: context?.tenant?.tenantId ?? context?.principal?.tenantId,
    },
    metadata,
    diagnostics,
  };
}

export class AuthenticationDomainException extends FrameworkException {
  constructor(
    code: string,
    message: string,
    metadata: Readonly<Record<string, unknown>> = {},
    cause?: unknown,
    diagnostics: Readonly<Record<string, unknown>> = {},
  ) {
    super(code, message, options(metadata, cause, diagnostics));
  }
}

export class AuthenticationUserNotFoundException extends ContractUserNotFoundException {
  constructor(userId?: string) {
    super(userId, options());
  }
}

export class AuthenticationStateException extends AuthenticationDomainException {
  constructor(reason: string, cause?: unknown) {
    super(
      'AUTHENTICATION_STATE_INVALID',
      'Authentication state is invalid or expired',
      {},
      cause,
      { reason },
    );
  }
}

export class AuthenticationInputException extends AuthenticationDomainException {
  constructor(reason: string) {
    super(
      'AUTHENTICATION_INPUT_INVALID',
      'Authentication input is invalid',
      {},
      undefined,
      { reason },
    );
  }
}

export class GuestSignupException extends AuthenticationDomainException {
  constructor(reason: string, cause?: unknown) {
    super(
      'GUEST_SIGNUP_FAILED',
      'Guest sign-up could not be completed',
      {},
      cause,
      { reason },
    );
  }
}

export class AuthenticationUserAlreadyExistsException extends AuthenticationDomainException {
  constructor(field: 'username' | 'email', value: string) {
    super(
      'AUTHENTICATION_USER_ALREADY_EXISTS',
      `A user with this ${field} already exists`,
      { field },
      undefined,
      { conflictingValue: value },
    );
  }
}

export class AuthenticationPasswordPolicyException extends AuthenticationDomainException {
  constructor(detail: string) {
    super(
      'AUTHENTICATION_PASSWORD_POLICY',
      'Password does not meet the policy requirements',
      {},
      undefined,
      { detail },
    );
  }
}

export class AuthenticationUnauthorizedException extends AuthenticationDomainException {
  constructor(operation: string) {
    super(
      'AUTHENTICATION_UNAUTHORIZED',
      'Not authorized to perform this operation',
      { operation },
    );
  }
}

export class AuthenticationInternalException extends AuthenticationDomainException {
  constructor(operation: string, cause?: unknown) {
    super(
      'AUTHENTICATION_INTERNAL_ERROR',
      'An internal authentication error occurred',
      { operation },
      cause,
    );
  }
}

export class IdentityProviderException extends AuthenticationDomainException {
  constructor(
    provider: string,
    operation: string,
    status?: number,
    cause?: unknown,
  ) {
    super(
      'IDENTITY_PROVIDER_UNAVAILABLE',
      'The identity provider is temporarily unavailable',
      {},
      cause,
      { provider, operation, status },
    );
  }
}

export class IdentityProviderClientConfigurationException extends AuthenticationDomainException {
  constructor(operation: string, status?: number, cause?: unknown) {
    super(
      'IDENTITY_PROVIDER_CLIENT_CONFIGURATION_INVALID',
      'Authentication is temporarily unavailable',
      {},
      cause,
      { provider: 'keycloak', operation, status },
    );
  }
}

export class IdentityProviderAdminCredentialsException extends AuthenticationDomainException {
  constructor(operation: string, status?: number, cause?: unknown) {
    super(
      'IDENTITY_PROVIDER_ADMIN_CREDENTIALS_INVALID',
      'Identity provider administrator credentials are invalid',
      {},
      cause,
      { provider: 'keycloak', operation, status },
    );
  }
}

export class IdentityProviderAdminForbiddenException extends AuthenticationDomainException {
  constructor(operation: string, status?: number, cause?: unknown) {
    super(
      'IDENTITY_PROVIDER_ADMIN_FORBIDDEN',
      'The identity provider administrator lacks the required permissions',
      {},
      cause,
      { provider: 'keycloak', operation, status },
    );
  }
}

export class IdentityProviderRateLimitedException extends AuthenticationDomainException {
  constructor(operation: string, status?: number, cause?: unknown) {
    super(
      'IDENTITY_PROVIDER_RATE_LIMITED',
      'The identity provider is temporarily rate limited',
      {},
      cause,
      { provider: 'keycloak', operation, status },
    );
  }
}

export class IdentityProviderResponseException extends AuthenticationDomainException {
  constructor(operation: string, status?: number, cause?: unknown) {
    super(
      'IDENTITY_PROVIDER_RESPONSE_INVALID',
      'The identity provider returned an invalid response',
      {},
      cause,
      { provider: 'keycloak', operation, status },
    );
  }
}

export class IdentityProviderRequestRejectedException extends AuthenticationDomainException {
  constructor(
    operation: string,
    status?: number,
    oauthError?: string,
    cause?: unknown,
  ) {
    super(
      'IDENTITY_PROVIDER_REQUEST_REJECTED',
      'The identity provider rejected the request',
      {},
      cause,
      {
        provider: 'keycloak',
        operation,
        status,
        oauthError,
      },
    );
  }
}
