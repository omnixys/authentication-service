import type { AddSecurityQuestionInput } from './security-question.dto.js';

/**
 * Input type for creating a new user.
 * Corresponds to fields in the User entity.
 */
export interface KCSignUpDTO {
  id: string;
  username: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  securityQuestions?: AddSecurityQuestionInput[];
}
