import { SecurityQuestionEnum } from '../enums/question.enum.js';
import { Field, InputType } from '@nestjs/graphql';
import { IsString } from 'class-validator';

@InputType()
export class SecurityQuestionInput {
  @Field(() => String)
  @IsString()
  question!: string;

  @Field(() => String)
  @IsString()
  key!: SecurityQuestionEnum;
}
