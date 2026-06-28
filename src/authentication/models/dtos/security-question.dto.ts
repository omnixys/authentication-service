// add-security-question.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { AddSecurityQuestionDTO } from '@omnixys/contracts';

@InputType()
export class AddSecurityQuestionInput implements AddSecurityQuestionDTO {
  @Field()
  questionId!: string;

  @Field()
  answer!: string;
}
