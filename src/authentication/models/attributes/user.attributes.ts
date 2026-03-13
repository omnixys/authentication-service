/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

import type { RealmRoleType } from '@omnixys/contracts';

// Zentrales, typsicheres Attribut-Schema für Keycloak-User-Attributes

export const PHONE_RE = /^\+?[0-9 .\-()]{6,20}$/;

export const KC_ATTRIBUTES = {
  privatePhone: { multi: false, kind: 'PHONE', re: PHONE_RE },
  workPhone: { multi: false, kind: 'PHONE', re: PHONE_RE },
  whatsappPhone: { multi: false, kind: 'PHONE', re: PHONE_RE },

  phoneNumbers: { multi: true, kind: 'PHONE', re: PHONE_RE },

  ticketIds: { multi: true, kind: 'ID' },
  invitationIds: { multi: true, kind: 'ID' },
  roles: { multi: true, kind: 'Role' },
} as const;

export type KcAttributeKey = keyof typeof KC_ATTRIBUTES;

export type MultiValuedKey = {
  [K in KcAttributeKey]: (typeof KC_ATTRIBUTES)[K]['multi'] extends true
    ? K
    : never;
}[KcAttributeKey];

export type SingleValuedKey = Exclude<KcAttributeKey, MultiValuedKey>;

// Input-Typen (Single → string | null | undefined; Multi → string|string[]|null|undefined)
export type KcAttributeInput = Partial<
  {
    [K in SingleValuedKey]: string | null | undefined;
  } & {
    [K in MultiValuedKey]: string | string[] | null | undefined | RealmRoleType;
  }
>;

export function isKcAttributeKey(v: string): v is KcAttributeKey {
  return v in KC_ATTRIBUTES;
}

// Normalisiert Werte zu string[] (Keycloak-Form), validiert nach Schema, wirft bei Verstoß
export function normalizeAttributeValue<K extends KcAttributeKey>(
  key: K,
  value: KcAttributeInput[K],
  mode: 'set' | 'append' | 'remove' = 'set',
): string[] {
  const def = KC_ATTRIBUTES[key];

  // remove: null/[] => komplettes Attribut löschen (→ [])
  if (
    mode === 'remove' &&
    (value == null || (Array.isArray(value) && value.length === 0))
  ) {
    return [];
  }

  const arr =
    value == null
      ? []
      : (Array.isArray(value) ? value : [value])
          .map((s) => String(s).trim())
          .filter((s) => s.length > 0);

  // Validierung
  if (def.kind === 'PHONE' && def.re) {
    for (const s of arr) {
      if (!def.re.test(s)) {
        throw new Error(`Invalid phone format for ${key}: "${s}"`);
      }
    }
  }

  // Für Single-Value-Keys maximal ein Eintrag
  if (!def.multi) {
    return arr.slice(0, 1);
  }
  // Multi: Dedupe
  return Array.from(new Set(arr));
}
