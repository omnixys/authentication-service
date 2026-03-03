import type { PhoneNumberInput } from '@omnixys/graphql';

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type PendingContact = {
  id: string; // random id (uuid/cuid)
  invitationId: string;
  email?: string;
  phoneNumbers?: PhoneNumberInput[];
  createdAt: number; // epoch ms
};
