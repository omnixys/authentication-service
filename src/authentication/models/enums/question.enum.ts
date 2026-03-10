import { registerEnumType } from '@nestjs/graphql';

export enum SecurityQuestionEnum {
  FIRST_PET = 'FIRST_PET',
  BIRTH_CITY = 'BIRTH_CITY',
  MOTHER_MAIDEN_NAME = 'MOTHER_MAIDEN_NAME',
  FAVORITE_SCHOOL_SUBJECT = 'FAVORITE_SCHOOL_SUBJECT',
  CHILDHOOD_BEST_FRIEND = 'CHILDHOOD_BEST_FRIEND',
  FAVOURITE_COMPANY = 'FAVOURITE_COMPANY',
  BIRTH_DATE = 'BIRTH_DATE',
}

registerEnumType(SecurityQuestionEnum, {
  name: 'SecurityQuestionEnum',
  description: 'Specifies the type/category of a phone number.',
});
