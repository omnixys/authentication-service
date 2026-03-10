import type { SecurityQuestion } from '../../../prisma/generated/client.js';
import type { SecurityQuestionEnum } from '../enums/question.enum.js';
import type { SecurityQuestionPayload } from '../payloads/security-question.payload.js';

export class SecurityQuestionMapper {
  static toPayload(question: SecurityQuestion): SecurityQuestionPayload {
    return {
      id: question.id,
      question: question.question,
      key: question.key as SecurityQuestionEnum,
    };
  }

  static toPayloadList(
    questions: SecurityQuestion[],
  ): SecurityQuestionPayload[] {
    return questions.map((question) => this.toPayload(question));
  }
}
