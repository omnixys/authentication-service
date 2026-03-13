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

import type { KeycloakTokenPayload } from '../dtos/kc-token.dto.js';
import type { KeycloakUser } from '../dtos/kc-user.dto.js';
import type { KcUser } from '../entitys/user.entity.js';
import { toEnumRoles, type RealmRoleType } from '@omnixys/contracts';

/**
 * Ist es ein Admin-API-User?
 */
function isKeycloakUser(
  v: KeycloakUser | KeycloakTokenPayload,
): v is KeycloakUser {
  return (
    typeof (v as KeycloakUser)?.id === 'string' &&
    typeof (v as KeycloakUser)?.username === 'string' &&
    typeof (v as KeycloakUser)?.email === 'string'
  );
}

/**
 * Aus KC-Admin-API → Domain
 * - attributes: phoneNumbers[] (frei), privatePhone/workPhone/whatsappPhone (single)
 * - ticketIds[]/invitationIds[]
 */
function fromKeycloakUser(u: KeycloakUser): KcUser {
  return {
    id: u.id ?? 'N/A',
    username: u.username,
    firstName: u.firstName ?? 'N/A',
    lastName: u.lastName ?? 'N/A',
    email: u.email,
  };
}

/**
 * Aus Access-Token → Domain
 * - nutzt camelCase Claims aus deinem ClientScope („checkpoint-main-extra“)
 */
function fromTokenPayload(p: KeycloakTokenPayload): KcUser {
  const realmRolesStr: string[] = Array.isArray(p.realm_access?.roles)
    ? p.realm_access.roles
    : [];

  // Merge + Enum-Normalisierung
  const roles: RealmRoleType[] = toEnumRoles([...realmRolesStr]);

  return {
    id: p.sub ?? 'N/A',
    username: p.username ?? 'N/A',
    firstName: p.first_name ?? 'N/A',
    lastName: p.last_name ?? 'N/A',
    email: p.email ?? 'N/A',
    roles,
  };
}

/** Liste von Admin-API-Usern → Domain */
export function toUsers(usersRaw: readonly KeycloakUser[]): KcUser[] {
  return usersRaw.map(fromKeycloakUser);
}

/** Overloads */
export function toUser(src: KeycloakUser): KcUser;
export function toUser(src: KeycloakTokenPayload): KcUser;
export function toUser(src: KeycloakUser | KeycloakTokenPayload): KcUser {
  return isKeycloakUser(src) ? fromKeycloakUser(src) : fromTokenPayload(src);
}

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

/** Optionaler Wrapper (falls du es so in DI/Docs magst) */
export class UserMappers {
  static toUsers(usersRaw: readonly KeycloakUser[]): KcUser[] {
    return toUsers(usersRaw);
  }
  static toUser(src: KeycloakUser | KeycloakTokenPayload): KcUser {
    return toUser(src);
  }
}
