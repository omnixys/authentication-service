/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */

import { JsonScalar } from '../../core/scalars/json.scalar.js';
import { LoggerPlusService } from '../../logger/logger-plus.service.js';
import { RequestMeta } from '../models/dtos/request-meta.dto.js';
import { MfaPreference } from '../models/dtos/reset-verification-result.dto.js';
import { ResetService } from '../services/reset.service.js';
import { BadRequestException } from '@nestjs/common';
import {
  Args,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Resolver,
} from '@nestjs/graphql';
import { ClientInfo } from '@omnixys/context';
import { ClientInfo as ClientInfoType } from '@omnixys/contracts';
import { AuthenticationResponseJSON } from '@simplewebauthn/server';

/* =======================================================
   GraphQL Types
======================================================= */

@ObjectType()
export class ResetVerificationPayload {
  @Field(() => Boolean)
  mfaRequired!: boolean;

  @Field(() => MfaPreference)
  mfaMethod!: MfaPreference;

  /**
   * Optional: you can expose a reset correlation id here if you store it.
   * For now we keep it minimal and do NOT expose internals.
   */
}

/* =======================================================
   GraphQL Inputs
======================================================= */

@InputType()
export class SecurityQuestionAnswerInput {
  @Field(() => String)
  questionId!: string;

  @Field(() => String)
  answer!: string;
}

@InputType()
export class StepUpVerificationInputGql {
  @Field(() => String)
  token!: string;

  /**
   * Used for TOTP and backup codes.
   */
  @Field(() => String, { nullable: true })
  code?: string;

  /**
   * WebAuthn client response JSON.
   * Use GraphQLJSON to avoid brittle schema coupling.
   */
  @Field(() => JsonScalar, { nullable: true })
  credentialResponse?: AuthenticationResponseJSON;

  /**
   * Security questions.
   */
  @Field(() => [SecurityQuestionAnswerInput], { nullable: true })
  answers?: SecurityQuestionAnswerInput[];
}

@InputType()
export class CompleteResetInputGql {
  @Field(() => String)
  token!: string;

  @Field(() => String)
  newPassword!: string;
}

/* =======================================================
   Resolver
======================================================= */

@Resolver()
export class ResetMutationResolver {
  private readonly logger;

  constructor(
    private readonly resetService: ResetService,
    private readonly loggerService: LoggerPlusService,
  ) {
    this.logger = this.loggerService.getLogger(this.constructor.name);
  }

  /**
   * Requests a password reset email.
   *
   * - Must not leak whether the user exists.
   * - Always returns true.
   */
  @Mutation(() => Boolean)
  async requestPasswordReset(
    @Args('email', { type: () => String }) email: string,
    @ClientInfo() client: ClientInfoType,
  ): Promise<boolean> {
    try {
      const context: RequestMeta = {
        ip: client.ip,
        device: client.device,
        locale: client.locale,
        location: client.location,
      };
      await this.resetService.requestReset(email, context);
    } catch (error) {
      // Intentionally swallow errors to avoid leaking account existence.
      // Log internally for monitoring & auditing.
      this.logger.warn('Password reset request failed silently', {
        email,
        ip: client.ip,
        error: error instanceof Error ? error.message : 'unknown',
      });
    }

    return true;
  }
  /**
   * Verifies the email token.
   * Returns whether step-up is required and which MFA method is expected.
   */
  @Mutation(() => ResetVerificationPayload)
  async verifyPasswordResetToken(
    @Args('token', { type: () => String }) token: string,
  ): Promise<ResetVerificationPayload> {
    return this.resetService.verifyResetToken(token);
  }

  /**
   * Performs step-up verification depending on user's MFA preference.
   */
  @Mutation(() => Boolean)
  async verifyPasswordResetStepUp(
    @Args('input', { type: () => StepUpVerificationInputGql })
    input: StepUpVerificationInputGql,
  ): Promise<boolean> {
    await this.resetService.verifyStepUp({
      token: input.token,
      code: input.code,
      credentialResponse: input.credentialResponse,
      answers: input.answers,
    } as any);

    return true;
  }

  /**
   * Completes reset: set password in Keycloak + invalidate sessions + invalidate reset tokens.
   */
  @Mutation(() => Boolean)
  async completePasswordReset(
    @Args('input', { type: () => CompleteResetInputGql })
    input: CompleteResetInputGql,
  ): Promise<boolean> {
    if (!input.newPassword || input.newPassword.length < 12) {
      throw new BadRequestException('Password does not meet requirements');
    }

    await this.resetService.completeReset({
      token: input.token,
      newPassword: input.newPassword,
    } as any);

    return true;
  }
}
