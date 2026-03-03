/* eslint-disable @typescript-eslint/explicit-function-return-type */

import { PrismaService } from '../../prisma/prisma.service.js';
import { Argon2Service } from './argon2.service.js';
import { Injectable, BadRequestException } from '@nestjs/common';

export interface AddSecurityQuestionAnswerInput {
  questionId: string;
  answer: string;
}

export interface VerifySecurityAnswerInput {
  questionId: string;
  answer: string;
}

@Injectable()
export class SecurityQuestionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly argon: Argon2Service,
  ) {}

  // --------------------------------------------------
  // Admin: create controlled question
  // --------------------------------------------------
  async addSecurityQuestion(question: string) {
    return this.prisma.securityQuestion.create({
      data: { question: question.trim() },
    });
  }

  async removeSecurityQuestion(questionId: string) {
    return this.prisma.securityQuestion.delete({
      where: { id: questionId },
    });
  }

  // --------------------------------------------------
  // User: add answer to predefined question
  // --------------------------------------------------
  async addSecurityQuestionAnswer(userId: string, input: AddSecurityQuestionAnswerInput) {
    const question = await this.prisma.securityQuestion.findUnique({
      where: { id: input.questionId },
    });

    if (!question) {
      throw new BadRequestException('Invalid security question');
    }

    const existing = await this.prisma.userSecurityQuestion.findUnique({
      where: {
        userId_questionId: {
          userId,
          questionId: input.questionId,
        },
      },
    });

    if (existing) {
      throw new BadRequestException('Security question already configured');
    }

    const answerHash = await this.argon.hash(input.answer);

    return this.prisma.userSecurityQuestion.create({
      data: {
        userId,
        questionId: input.questionId,
        answerHash,
      },
    });
  }

  async removeSecurityQuestionAnswer(userId: string, questionId: string) {
    return this.prisma.userSecurityQuestion.delete({
      where: {
        userId_questionId: {
          userId,
          questionId,
        },
      },
    });
  }

  // --------------------------------------------------
  // Verify answers
  // --------------------------------------------------
  async verifyAnswers(userId: string, answers: VerifySecurityAnswerInput[]): Promise<boolean> {
    if (!answers?.length) {
      return false;
    }

    const records = await this.prisma.userSecurityQuestion.findMany({
      where: { userId },
    });

    if (records.length === 0) {
      return false;
    }

    for (const answer of answers) {
      const record = records.find((r) => r.questionId === answer.questionId);

      if (!record) {
        return false;
      }

      const valid = await this.argon.verify(record.answerHash, answer.answer);

      if (!valid) {
        return false;
      }
    }

    return true;
  }
}
