import type { PhoneNumberInput } from '@omnixys/graphql';

export interface UserDTO extends UserUpdateDTO {
  username: string;
  phoneNumbers?: PhoneNumberInput[];
  invitationId?: string;
}

export interface UserUpdateDTO {
  id: string;
  firstName?: string;
  lastName?: string;
  email?: string;
}
