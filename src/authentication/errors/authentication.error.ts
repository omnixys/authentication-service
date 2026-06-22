import { ContextAccessor } from '@omnixys/context';
import {
  FrameworkException,
  UserNotFoundException as ContractUserNotFoundException,
  type FrameworkExceptionOptions,
} from '@omnixys/contracts';

function options(
  metadata: Readonly<Record<string, unknown>> = {},
  cause?: unknown,
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
  };
}

export class AuthenticationDomainException extends FrameworkException {
  constructor(
    code: string,
    message: string,
    metadata: Readonly<Record<string, unknown>> = {},
    cause?: unknown,
  ) {
    super(code, message, options(metadata, cause));
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
      { reason },
      cause,
    );
  }
}

export class AuthenticationInputException extends AuthenticationDomainException {
  constructor(reason: string) {
    super('AUTHENTICATION_INPUT_INVALID', 'Authentication input is invalid', {
      reason,
    });
  }
}

export class GuestSignupException extends AuthenticationDomainException {
  constructor(reason: string, cause?: unknown) {
    super(
      'GUEST_SIGNUP_FAILED',
      'Guest sign-up could not be completed',
      { reason },
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
      'Identity provider request failed',
      { provider, operation, status },
      cause,
    );
  }
}
