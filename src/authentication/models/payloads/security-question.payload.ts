import { SecurityQuestionEnum } from '../enums/question.enum.js';
import { Field, ID, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class SecurityQuestionPayload {
  @Field(() => ID)
  id!: string;

  @Field(() => String)
  question!: string;

  @Field(() => SecurityQuestionEnum)
  key!: SecurityQuestionEnum;
}
