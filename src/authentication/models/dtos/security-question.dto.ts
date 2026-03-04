// add-security-question.input.ts
import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class AddSecurityQuestionInput {
  @Field()
  questionId!: string;

  @Field()
  answer!: string;
}
